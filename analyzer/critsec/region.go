package critsec

import (
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ssa"
)

// region is a critical section: the calls that run while a transaction is
// open or a mutex is held.
type region struct {
	rule  string
	what  string // "the transaction" or "the lock on mu"
	fn    *ssa.Function
	start token.Pos
	calls []ssa.CallInstruction
}

// regions finds the critical sections of fn.
func regions(fn *ssa.Function) []region {
	var out []region
	for _, b := range fn.Blocks {
		for i, instr := range b.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			pkg, recv, name := callee(call.Common())
			switch {
			case beginsTx(pkg, recv, name):
				if tx := txValue(call); tx != nil {
					out = append(out, region{rule: TxNetworkIO, what: "the transaction", fn: fn, start: call.Pos(),
						calls: walk(b, i+1, func(c ssa.CallInstruction) bool { return endsTx(c, tx) })})
				}
			case txCallback(pkg, recv, name):
				for _, cb := range callbackFuncs(call) {
					out = append(out, region{rule: TxNetworkIO, what: "the transaction", fn: fn, start: call.Pos(), calls: allCalls(cb)})
				}
			case pkg == "sync" && (recv == "Mutex" || recv == "RWMutex") && (name == "Lock" || name == "RLock"):
				mu := receiver(call.Common())
				unlock := "Unlock"
				if name == "RLock" {
					unlock = "RUnlock"
				}
				out = append(out, region{rule: LockBlockingIO, what: "the lock", fn: fn, start: call.Pos(),
					calls: walk(b, i+1, func(c ssa.CallInstruction) bool { return unlocks(c, mu, unlock) })})
			}
		}
	}
	return out
}

func beginsTx(pkg, recv, name string) bool {
	switch {
	case pkg == "database/sql" && (recv == "DB" || recv == "Conn"):
		return name == "Begin" || name == "BeginTx"
	case pkg == "github.com/jmoiron/sqlx" && recv == "DB":
		return name == "Beginx" || name == "BeginTxx" || name == "MustBegin" || name == "MustBeginTx"
	case isPgx(pkg) && (recv == "Conn" || recv == "Pool"):
		return name == "Begin" || name == "BeginTx"
	case pkg == "gorm.io/gorm" && recv == "DB":
		return name == "Begin"
	}
	return false
}

func txCallback(pkg, recv, name string) bool {
	switch {
	case pkg == "gorm.io/gorm" && recv == "DB":
		return name == "Transaction"
	case isPgx(pkg) && recv == "":
		return name == "BeginFunc" || name == "BeginTxFunc"
	case isPgx(pkg) && (recv == "Conn" || recv == "Pool"):
		return name == "BeginFunc" || name == "BeginTxFunc"
	case pkg == "github.com/jmoiron/sqlx" && recv == "":
		return false
	}
	return false
}

func isPgx(pkg string) bool {
	return pkg == "github.com/jackc/pgx/v5" || pkg == "github.com/jackc/pgx/v4" ||
		pkg == "github.com/jackc/pgx/v5/pgxpool" || pkg == "github.com/jackc/pgx/v4/pgxpool"
}

// txValue returns the transaction value produced by a begin call.
func txValue(call *ssa.Call) ssa.Value {
	if _, ok := call.Type().(*types.Tuple); !ok {
		return call // single result, such as gorm's (*DB).Begin
	}
	for _, ref := range *call.Referrers() {
		if ex, ok := ref.(*ssa.Extract); ok && ex.Index == 0 {
			return ex
		}
	}
	return nil
}

// endsTx reports whether c commits or rolls back tx. A deferred call does not
// end the region where it is registered.
func endsTx(c ssa.CallInstruction, tx ssa.Value) bool {
	if _, deferred := c.(*ssa.Defer); deferred {
		return false
	}
	_, _, name := callee(c.Common())
	if name != "Commit" && name != "Rollback" {
		return false
	}
	return sameValue(receiver(c.Common()), tx)
}

func unlocks(c ssa.CallInstruction, mu ssa.Value, method string) bool {
	if _, deferred := c.(*ssa.Defer); deferred {
		return false
	}
	pkg, _, name := callee(c.Common())
	return pkg == "sync" && name == method && sameValue(receiver(c.Common()), mu)
}

// receiver returns the receiver of a method call, or nil.
func receiver(common *ssa.CallCommon) ssa.Value {
	if common.IsInvoke() {
		return common.Value
	}
	if fn := common.StaticCallee(); fn != nil && fn.Signature.Recv() != nil && len(common.Args) > 0 {
		return common.Args[0]
	}
	return nil
}

// sameValue reports whether a and b denote the same variable: the same SSA
// value, or field addresses with the same field of the same base.
func sameValue(a, b ssa.Value) bool {
	a, b = strip(a), strip(b)
	if a == nil || b == nil {
		return false
	}
	if a == b {
		return true
	}
	fa, ok1 := a.(*ssa.FieldAddr)
	fb, ok2 := b.(*ssa.FieldAddr)
	if ok1 && ok2 {
		return fa.Field == fb.Field && sameValue(fa.X, fb.X)
	}
	la, ok1 := a.(*ssa.UnOp)
	lb, ok2 := b.(*ssa.UnOp)
	if ok1 && ok2 && la.Op == token.MUL && lb.Op == token.MUL {
		return sameValue(la.X, lb.X)
	}
	return false
}

func strip(v ssa.Value) ssa.Value {
	for {
		switch x := v.(type) {
		case *ssa.ChangeType:
			v = x.X
		case *ssa.MakeInterface:
			v = x.X
		case *ssa.ChangeInterface:
			v = x.X
		default:
			return v
		}
	}
}

// walk returns the calls reachable from instruction i of block b without
// passing a call for which stop returns true. Function exits end the walk.
func walk(b *ssa.BasicBlock, i int, stop func(ssa.CallInstruction) bool) []ssa.CallInstruction {
	var out []ssa.CallInstruction
	type item struct {
		block *ssa.BasicBlock
		index int
	}
	seen := map[*ssa.BasicBlock]bool{}
	work := []item{{b, i}}
	for len(work) > 0 {
		it := work[len(work)-1]
		work = work[:len(work)-1]
		stopped := false
		for _, instr := range it.block.Instrs[it.index:] {
			c, ok := instr.(ssa.CallInstruction)
			if !ok {
				continue
			}
			if stop(c) {
				stopped = true
				break
			}
			out = append(out, c)
		}
		if stopped {
			continue
		}
		for _, succ := range it.block.Succs {
			if !seen[succ] {
				seen[succ] = true
				work = append(work, item{succ, 0})
			}
		}
	}
	return out
}

// callbackFuncs returns the function values passed to a transaction helper.
func callbackFuncs(call *ssa.Call) []*ssa.Function {
	var out []*ssa.Function
	for _, arg := range call.Common().Args {
		switch v := arg.(type) {
		case *ssa.Function:
			out = append(out, v)
		case *ssa.MakeClosure:
			if fn, ok := v.Fn.(*ssa.Function); ok {
				out = append(out, fn)
			}
		}
	}
	return out
}

func allCalls(fn *ssa.Function) []ssa.CallInstruction {
	var out []ssa.CallInstruction
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			if c, ok := instr.(ssa.CallInstruction); ok {
				out = append(out, c)
			}
		}
	}
	return out
}

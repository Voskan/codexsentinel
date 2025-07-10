package testdata

import (
	"fmt"
)

// ComplexFunction demonstrates a function with high cyclomatic complexity,
// deep nesting, and multiple branches, used for test purposes.
func ComplexFunction(a int, b int, flag bool) string {
	var result string

	if a > 0 {
		for i := 0; i < a; i++ {
			switch {
			case i%2 == 0 && flag:
				result += fmt.Sprintf("Even:%d ", i)
			case i%3 == 0:
				result += fmt.Sprintf("Three:%d ", i)
			case i%5 == 0:
				result += fmt.Sprintf("Five:%d ", i)
			default:
				if b > 10 {
					for j := 0; j < b; j++ {
						if j%2 == 1 {
							result += fmt.Sprintf("Nested:%d-%d ", i, j)
						}
					}
				}
			}
		}
	} else if a < 0 {
		for k := 0; k > a; k-- {
			if k == -3 {
				break
			}
			result += "Negative loop "
		}
	} else {
		result = "Zero"
	}

	return result
}

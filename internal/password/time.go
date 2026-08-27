package password

import (
	"fmt"
	"math"
)

func formatTime(seconds float64) string {
	const day = 24 * 60 * 60
	const year = 365 * day

	switch {
	case math.IsInf(seconds, 1) || seconds > 3e17:
		return "longer than the universe"
	case seconds < 0.001:
		return "instantly"
	case seconds < 1:
		return fmt.Sprintf("%.0f ms", seconds*1000)
	case seconds < 60:
		return fmt.Sprintf("%.0f seconds", seconds)
	case seconds < 60*60:
		return fmt.Sprintf("%.0f minutes", seconds/60)
	case seconds < day:
		return fmt.Sprintf("%.0f hours", seconds/(60*60))
	case seconds < year:
		return fmt.Sprintf("%.0f days", seconds/day)
	case seconds < 100*year:
		return fmt.Sprintf("%.0f years", seconds/year)
	default:
		return fmt.Sprintf("%.0f centuries", seconds/(100*year))
	}
}

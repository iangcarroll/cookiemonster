package monster

type limiter struct {
	ch chan struct{}
}

// Creates a new `limiter` which uses Go channels to throttle how many
// goroutines execute at a time.
func newLimiter(concurrencyLimit uint64) *limiter {
	return &limiter{make(chan struct{}, concurrencyLimit)}
}

func (l *limiter) Add() {
	l.ch <- struct{}{}
}

func (l *limiter) Done() {
	<-l.ch
}

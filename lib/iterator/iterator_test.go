package iterator_test

import (
	"fmt"
	"testing"

	"github.com/sourcegraph/sourcegraph/lib/errors"
	"github.com/sourcegraph/sourcegraph/lib/iterator"
	"github.com/stretchr/testify/assert"
)

func ExampleIterator() {
	x := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	it := iterator.New(func() ([]int, error) {
		if len(x) == 0 {
			return nil, nil
		}
		y := x[:2]
		x = x[2:]
		return y, nil
	})

	for it.Next() {
		fmt.Printf("%d ", it.Current())
	}

	if it.Err() != nil {
		fmt.Println(it.Err())
	}

	// Output: 1 2 3 4 5 6 7 8 9 10
}

func TestIterator_Err(t *testing.T) {
	assert := assert.New(t)

	sendErr := false
	it := iterator.New(func() ([]int, error) {
		var err error
		if sendErr {
			err = errors.New("boom")
		}
		sendErr = true
		// We always return items, to test that we stop collecting after err.
		return []int{1, 2, 3}, err
	})

	got, err := iterator.Collect(it)
	assert.Equal([]int{1, 2, 3}, got)
	assert.ErrorContains(err, "boom")

	// Double check it is safe to call Next and Err again.
	assert.Falsef(it.Next(), "expected collected Next to return false")
	assert.Errorf(it.Err(), "expected collected Err to be non-nil")

	// Ensure we panic on calling Current.
	assert.Panics(func() { it.Current() })
}

func TestIterator_Current(t *testing.T) {
	assert := assert.New(t)

	it := iterator.From([]int{1})
	assert.PanicsWithValue(
		"*iterator.Iterator[int].Current() called before first call to Next()",
		func() { it.Current() },
		"Current before Next should panic",
	)

	assert.True(it.Next())
	assert.Equal(1, it.Current())
	assert.Equal(1, it.Current(), "Current should be idempotent")

	assert.False(it.Next())
	assert.PanicsWithValue(
		"*iterator.Iterator[int].Current() called after Next() returned false",
		func() { it.Current() },
		"Current after Next is false should panic",
	)
}

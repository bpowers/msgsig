// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

package msgsig

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContains(t *testing.T) {
	cases := []struct {
		slice    []string
		str      string
		expected bool
	}{
		{
			slice:    []string{},
			str:      "",
			expected: false,
		},
		{
			slice:    []string{"a", "b", "c"},
			str:      "aa",
			expected: false,
		},
		{
			slice:    []string{"a", "b", "c"},
			str:      "b",
			expected: true,
		},
	}

	for _, test := range cases {
		actual := contains(test.slice, test.str)
		require.Equal(t, test.expected, actual)
	}
}

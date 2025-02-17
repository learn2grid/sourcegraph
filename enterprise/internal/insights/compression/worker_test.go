package compression

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hexops/autogold"
	"golang.org/x/time/rate"

	"github.com/sourcegraph/sourcegraph/internal/api"
	"github.com/sourcegraph/sourcegraph/internal/conf"
	"github.com/sourcegraph/sourcegraph/internal/database"
	"github.com/sourcegraph/sourcegraph/internal/gitserver/gitdomain"
	"github.com/sourcegraph/sourcegraph/internal/observation"
	"github.com/sourcegraph/sourcegraph/internal/ratelimit"
	"github.com/sourcegraph/sourcegraph/lib/errors"
	"github.com/sourcegraph/sourcegraph/schema"
)

var ops *operations = newOperations(&observation.TestContext)

func TestCommitIndexer_indexAll(t *testing.T) {
	ctx := context.Background()
	commitStore := NewMockCommitStore()

	maxHistorical := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC) }

	indexer := CommitIndexer{
		limiter:           ratelimit.NewInstrumentedLimiter("TestCommitIndexer", rate.NewLimiter(10, 1)),
		commitStore:       commitStore,
		maxHistoricalTime: maxHistorical,
		background:        context.Background(),
		operations:        ops,
		clock:             clock,
	}

	// Testing a scenario with 3 repos
	// "repo-one" has commits but has disabled indexing
	// "really-big-repo" has commits and has enabled indexing, it should update
	// "no-commits" has no commits but is enabled, and will not update the index but will update the metadata
	commits := map[string][]*gitdomain.Commit{
		"repo-one": {
			commit("ref1", "2020-05-01T00:00:00+00:00"),
			commit("ref2", "2020-05-10T00:00:00+00:00"),
			commit("ref3", "2020-05-15T00:00:00+00:00"),
			commit("ref4", "2020-05-20T00:00:00+00:00"),
		},
		"really-big-repo": {
			commit("bigref1", "1999-04-01T00:00:00+00:00"),
			commit("bigref2", "1999-04-03T00:00:00+00:00"),
			commit("bigref3", "1999-04-06T00:00:00+00:00"),
			commit("bigref4", "1999-04-09T00:00:00+00:00"),
		},
		"no-commits": {},
	}
	indexer.getCommits = mockCommits(commits)
	indexer.allReposIterator = mockIterator([]string{"repo-one", "really-big-repo", "no-commits"})

	commitStore.GetMetadataFunc.PushReturn(CommitIndexMetadata{
		RepoId:        1,
		Enabled:       false,
		LastIndexedAt: time.Date(1999, time.January, 1, 0, 0, 0, 0, time.UTC),
	}, nil)

	commitStore.GetMetadataFunc.PushReturn(CommitIndexMetadata{
		RepoId:        2,
		Enabled:       true,
		LastIndexedAt: time.Date(1999, time.January, 1, 0, 0, 0, 0, time.UTC),
	}, nil)

	commitStore.GetMetadataFunc.PushReturn(CommitIndexMetadata{
		RepoId:        3,
		Enabled:       true,
		LastIndexedAt: time.Date(1999, time.January, 1, 0, 0, 0, 0, time.UTC),
	}, nil)

	t.Run("multi_repository", func(t *testing.T) {
		windowDuration := 0
		conf.Mock(&conf.Unified{
			SiteConfiguration: schema.SiteConfiguration{
				InsightsCommitIndexerWindowDuration: windowDuration,
			},
		})
		defer conf.Mock(nil)
		err := indexer.indexAll(ctx)
		if err != nil {
			t.Fatal(err)
		}

		// Three repos get metadata, one is disabled, the other two are enabled
		if got, want := len(commitStore.GetMetadataFunc.history), 3; got != want {
			t.Errorf("got GetMetadata invocations: %v want %v", got, want)
		}

		// Both enabled repositories should call insert commits
		if got, want := len(commitStore.InsertCommitsFunc.history), 2; got != want {
			t.Errorf("got InsertCommits invocations: %v want %v", got, want)
		} else {
			calls := map[string]CommitStoreInsertCommitsFuncCall{
				"really-big-repo": commitStore.InsertCommitsFunc.history[0],
				"no-commits":      commitStore.InsertCommitsFunc.history[1],
			}
			for repo, call := range calls {
				// Check Indexed though is the clock time
				if diff := cmp.Diff(clock(), call.Arg3); diff != "" {
					t.Errorf("unexpected indexed though date/time")
				}
				// Check the correct commits
				for i, got := range call.Arg2 {
					if diff := cmp.Diff(commits[repo][i], got); diff != "" {
						t.Errorf("unexpected commit\n%s", diff)
					}
				}
			}
		}
	})
}

func Test_getMetadata_InsertNewRecord(t *testing.T) {
	ctx := context.Background()
	commitStore := NewMockCommitStore()

	expected := CommitIndexMetadata{
		RepoId:        1,
		Enabled:       true,
		LastIndexedAt: time.Date(2018, 1, 1, 1, 1, 1, 1, time.UTC),
	}

	// this test will get no results from the metadata table and will insert one
	commitStore.GetMetadataFunc.PushReturn(CommitIndexMetadata{}, sql.ErrNoRows)
	commitStore.UpsertMetadataStampFunc.PushReturn(expected, nil)

	t.Run("create_new_metadata", func(t *testing.T) {
		metadata, err := getMetadata(ctx, 1, commitStore)
		if err != nil {
			t.Fatal(err)
		}

		if diff := cmp.Diff(expected, metadata); diff != "" {
			t.Errorf("unexpected metadata\n%s", diff)
		}

		if got, want := len(commitStore.GetMetadataFunc.history), 1; got != want {
			t.Errorf("unexpected GetMetadata invocations %v", 1)
		}

		if got, want := len(commitStore.UpsertMetadataStampFunc.history), 1; got != want {
			t.Errorf("unexpected UpsertMetadataStamp invocations %v", 1)
		}
	})
}

func Test_getMetadata_NoInsertRequired(t *testing.T) {
	ctx := context.Background()
	commitStore := NewMockCommitStore()

	expected := CommitIndexMetadata{
		RepoId:        1,
		Enabled:       true,
		LastIndexedAt: time.Date(2018, 1, 1, 1, 1, 1, 1, time.UTC),
	}
	// will get results immediately and will not insert a new row
	commitStore.GetMetadataFunc.PushReturn(expected, nil)

	t.Run("get_metadata", func(t *testing.T) {
		metadata, err := getMetadata(ctx, 1, commitStore)
		if err != nil {
			t.Fatal(err)
		}

		if diff := cmp.Diff(expected, metadata); diff != "" {
			t.Errorf("unexpected metadata\n%s", diff)
		}

		if got, want := len(commitStore.GetMetadataFunc.history), 1; got != want {
			t.Errorf("unexpected GetMetadata invocations %v", 1)
		}

		if got, want := len(commitStore.UpsertMetadataStampFunc.history), 0; got != want {
			t.Errorf("unexpected UpsertMetadataStamp invocations %v", 1)
		}
	})
}

func TestCommitIndexer_windowing(t *testing.T) {
	ctx := context.Background()
	commitStore := NewMockCommitStore()

	maxHistorical := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return time.Date(2020, time.June, 1, 0, 0, 0, 0, time.UTC) }

	indexer := CommitIndexer{
		limiter:           ratelimit.NewInstrumentedLimiter("TestCommitIndexer", rate.NewLimiter(10, 1)),
		commitStore:       commitStore,
		maxHistoricalTime: maxHistorical,
		background:        context.Background(),
		operations:        ops,
		clock:             clock,
	}

	// Testing a scenario with 3 repos and a window of 30 days
	// "repo-one" has been recently indexed and all commits are in one window
	// "really-big-repo" has 2 windows of commits
	// "no-commits-recent" has no commits and was recently indexed
	// "no-commits-not-recent" has no commits but is 2 windows behind on indexing
	commits := map[string][]*gitdomain.Commit{
		"repo-one": {
			commit("ref1", "2020-05-10T00:00:00+00:00"),
			commit("ref2", "2020-05-12T00:00:00+00:00"),
		},
		"really-big-repo": {
			commit("bigref1", "2020-04-17T00:00:00+00:00"),
			commit("bigref2", "2020-04-18T00:00:00+00:00"),
			commit("bigref3", "2020-05-17T00:00:00+00:00"),
			commit("bigref4", "2020-05-18T00:00:00+00:00"),
		},
		"no-commits-recent":     {},
		"no-commits-not-recent": {},
		"only-recent": {
			commit("bigref4", "2020-05-18T00:00:00+00:00"),
		},
	}
	indexer.getCommits = mockCommits(commits)
	indexer.allReposIterator = mockIterator([]string{"repo-one", "really-big-repo", "no-commits-recent", "no-commits-not-recent", "only-recent"})

	commitStore.GetMetadataFunc.PushReturn(CommitIndexMetadata{
		RepoId:        1,
		Enabled:       true,
		LastIndexedAt: time.Date(2020, time.May, 5, 0, 0, 0, 0, time.UTC),
	}, nil)

	commitStore.GetMetadataFunc.PushReturn(CommitIndexMetadata{
		RepoId:        2,
		Enabled:       true,
		LastIndexedAt: time.Date(2020, time.April, 5, 0, 0, 0, 0, time.UTC),
	}, nil)

	commitStore.GetMetadataFunc.PushReturn(CommitIndexMetadata{
		RepoId:        2,
		Enabled:       true,
		LastIndexedAt: time.Date(2020, time.May, 5, 0, 0, 0, 0, time.UTC),
	}, nil)

	commitStore.GetMetadataFunc.PushReturn(CommitIndexMetadata{
		RepoId:        3,
		Enabled:       true,
		LastIndexedAt: time.Date(2020, time.May, 5, 0, 0, 0, 0, time.UTC),
	}, nil)

	commitStore.GetMetadataFunc.PushReturn(CommitIndexMetadata{
		RepoId:        4,
		Enabled:       true,
		LastIndexedAt: time.Date(2020, time.April, 5, 0, 0, 0, 0, time.UTC),
	}, nil)

	commitStore.GetMetadataFunc.PushReturn(CommitIndexMetadata{
		RepoId:        4,
		Enabled:       true,
		LastIndexedAt: time.Date(2020, time.May, 5, 0, 0, 0, 0, time.UTC),
	}, nil)

	commitStore.GetMetadataFunc.PushReturn(CommitIndexMetadata{
		RepoId:        5,
		Enabled:       true,
		LastIndexedAt: time.Date(2020, time.April, 5, 0, 0, 0, 0, time.UTC),
	}, nil)

	commitStore.GetMetadataFunc.PushReturn(CommitIndexMetadata{
		RepoId:        5,
		Enabled:       true,
		LastIndexedAt: time.Date(2020, time.May, 5, 0, 0, 0, 0, time.UTC),
	}, nil)

	endOfApril5Window := time.Date(2020, time.April, 5, 0, 0, 0, 0, time.UTC).Add(24 * 30 * time.Hour)

	t.Run("multi_repository_paging", func(t *testing.T) {
		conf.Mock(&conf.Unified{
			SiteConfiguration: schema.SiteConfiguration{
				InsightsCommitIndexerWindowDuration: 30,
			},
		})
		defer conf.Mock(nil)
		err := indexer.indexAll(ctx)
		if err != nil {
			t.Fatal(err)
		}

		// 4 enabled repos get metadata, repo 2, 4 and 5 need 2 windows all others just 1
		if got, want := len(commitStore.GetMetadataFunc.history), 8; got != want {
			t.Errorf("got GetMetadata invocations: %v want %v", got, want)
		}

		// Each time though we call insert commits even if there are none repo 2, 4 and 5 need 2 windows so 8 total
		if got, want := len(commitStore.InsertCommitsFunc.history), 8; got != want {
			t.Errorf("got InsertCommits invocations: %v want %v", got, want)
		} else {

			/* repo one
			** All commits present and sets last indexed to the clock time
			 */
			checkCommits(t, commits["repo-one"], commitStore.InsertCommitsFunc.history[0].Arg2)
			checkIndexedThough(t, clock().UTC(), commitStore.InsertCommitsFunc.history[0].Arg3)

			/* really-big-repo
			** Last indexed more than 1 window ago so needs to make 2 passes
			** First Pass:
			**    First two commits and sets last indxed to the end of the time window (last_indexed + 30 days)
			** Second Pass:
			**    Last two commits and sets last indexed to clock time because end of window was greater than clock
			 */
			checkCommits(t, commits["really-big-repo"][:2], commitStore.InsertCommitsFunc.history[1].Arg2)
			checkIndexedThough(t, endOfApril5Window, commitStore.InsertCommitsFunc.history[1].Arg3)
			checkCommits(t, commits["really-big-repo"][2:], commitStore.InsertCommitsFunc.history[2].Arg2)
			checkIndexedThough(t, clock().UTC(), commitStore.InsertCommitsFunc.history[2].Arg3)

			/* no-commits-recent
			** There are no commits to save and sets last indexed to the clock time
			 */
			checkCommits(t, []*gitdomain.Commit{}, commitStore.InsertCommitsFunc.history[3].Arg2)
			checkIndexedThough(t, clock().UTC(), commitStore.InsertCommitsFunc.history[3].Arg3)

			/* no-commits-not-recent
			** Last indexed is more than 1 window agao so need to make 2 passes
			** First Pass:
			**    No commits to save and sets last indxed to the end of the time window (last_indexed + 30 days)
			** Second Pass:
			**    Still no commits and sets last indexed to clock time
			 */
			checkCommits(t, []*gitdomain.Commit{}, commitStore.InsertCommitsFunc.history[4].Arg2)
			checkIndexedThough(t, endOfApril5Window, commitStore.InsertCommitsFunc.history[4].Arg3)
			checkCommits(t, []*gitdomain.Commit{}, commitStore.InsertCommitsFunc.history[5].Arg2)
			checkIndexedThough(t, clock().UTC(), commitStore.InsertCommitsFunc.history[5].Arg3)

			/* only-recent
			** Last indexed is more than 1 window agao so need to make 2 passes
			** First Pass:
			**    No commits to save and sets last indxed to the end of the time window (last_indexed + 30 days)
			** Second Pass:
			**    Saves the 1 commit and sets last indexed to clock time
			 */
			checkCommits(t, []*gitdomain.Commit{}, commitStore.InsertCommitsFunc.history[6].Arg2)
			checkIndexedThough(t, endOfApril5Window, commitStore.InsertCommitsFunc.history[6].Arg3)
			checkCommits(t, commits["only-recent"], commitStore.InsertCommitsFunc.history[7].Arg2)
			checkIndexedThough(t, clock().UTC(), commitStore.InsertCommitsFunc.history[7].Arg3)

		}
	})
}

func Test_IsEmptyRepoError(t *testing.T) {
	t.Parallel()

	defaultDate := time.Date(2022, 7, 1, 12, 12, 12, 10, time.UTC)
	defaultError := errors.New(generateEmptyRepoErrorMessagePrefix(defaultDate, nil) + emptyRepoErrMessageSuffix)

	testCases := []struct {
		err   error
		after time.Time
		until *time.Time
		want  autogold.Value
	}{
		{
			err:   defaultError,
			after: defaultDate,
			until: nil,
			want:  autogold.Want("EmptyRepo", true),
		},
		{
			err:   errors.Newf("Another message: %w", defaultError),
			after: defaultDate,
			until: nil,
			want:  autogold.Want("NestedEmptyRepoError", true),
		},
		{
			err:   errors.Newf("Another message: %w", errors.Newf("Deep nested: %w", defaultError)),
			after: defaultDate,
			until: nil,
			want:  autogold.Want("DeepNestedError", true),
		},
		{
			err:   errors.Newf("Another message: %w", errors.New("Not an empty repo")),
			after: time.Now(),
			until: nil,
			want:  autogold.Want("NestedNotEmptyRepoError", false),
		},
		{
			err:   errors.New(generateEmptyRepoErrorMessagePrefix(defaultDate, &defaultDate) + emptyRepoErrMessageSuffix),
			after: defaultDate,
			until: &defaultDate,
			want:  autogold.Want("EmptyRepoUntil", true),
		},
		{
			err:   errors.New(generateEmptyRepoErrorMessagePrefix(defaultDate, nil) + emptyRepoErrMessageSuffixWithNameOnly),
			after: defaultDate,
			want:  autogold.Want("EmptyRepoSubRepoPermissions", true),
		},
		{
			err:   errors.New(generateEmptyRepoErrorMessagePrefix(defaultDate, &defaultDate) + emptyRepoErrMessageSuffixWithNameOnly),
			after: defaultDate,
			until: &defaultDate,
			want:  autogold.Want("EmptyRepoUntilSubRepoPermissions", true),
		},
		{
			err:   errors.New("A different error"),
			after: time.Now(),
			until: nil,
			want:  autogold.Want("NotEmptyRepo", false),
		},
		{
			err:   nil,
			after: time.Now(),
			until: nil,
			want:  autogold.Want("NotAnError", false),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.want.Name(), func(t *testing.T) {
			got := isCommitEmptyRepoError(tc.err, tc.after, tc.until)
			tc.want.Equal(t, got)
		})
	}
}

func TestCommitIndexer_EmptyRepoError(t *testing.T) {
	ctx := context.Background()
	commitStore := NewMockCommitStore()

	maxHistorical := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC) }

	indexer := CommitIndexer{
		limiter:           ratelimit.NewInstrumentedLimiter("TestCommitIndexer", rate.NewLimiter(10, 1)),
		commitStore:       commitStore,
		maxHistoricalTime: maxHistorical,
		background:        context.Background(),
		operations:        ops,
		clock:             clock,
	}

	commits := map[string][]*gitdomain.Commit{
		"repo-one": {
			commit("ref1", "2020-05-01T00:00:00+00:00"),
			commit("ref2", "2020-05-10T00:00:00+00:00"),
			commit("ref3", "2020-05-15T00:00:00+00:00"),
			commit("ref4", "2020-05-20T00:00:00+00:00"),
		},
		"empty-repo": {},
	}
	indexer.getCommits = mockCommitsWithError(nil)
	indexer.allReposIterator = mockIterator([]string{"repo-one", "empty-repo"})

	commitStore.GetMetadataFunc.PushReturn(CommitIndexMetadata{
		RepoId:        1,
		Enabled:       true,
		LastIndexedAt: time.Date(1999, time.January, 1, 0, 0, 0, 0, time.UTC),
	}, nil)

	commitStore.GetMetadataFunc.PushReturn(CommitIndexMetadata{
		RepoId:        2,
		Enabled:       true,
		LastIndexedAt: time.Date(1999, time.January, 1, 0, 0, 0, 0, time.UTC),
	}, nil)

	windowDuration := 0
	conf.Mock(&conf.Unified{
		SiteConfiguration: schema.SiteConfiguration{
			InsightsCommitIndexerWindowDuration: windowDuration,
		},
	})
	defer conf.Mock(nil)
	err := indexer.indexAll(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Two repos get metadata
	if got, want := len(commitStore.GetMetadataFunc.history), 2; got != want {
		t.Errorf("got GetMetadata invocations: %v want %v", got, want)
	}

	// The two repos should call insert commits. Repo 2 is empty but its metadata is up to date.
	if got, want := len(commitStore.InsertCommitsFunc.history), 2; got != want {
		t.Errorf("got InsertCommits invocations: %v want %v", got, want)
	} else {
		calls := map[string]CommitStoreInsertCommitsFuncCall{
			"repo-one":   commitStore.InsertCommitsFunc.history[0],
			"empty-repo": commitStore.InsertCommitsFunc.history[1],
		}
		for repo, call := range calls {
			// Check Indexed though is the clock time
			if diff := cmp.Diff(clock(), call.Arg3); diff != "" {
				t.Errorf("unexpected indexed though date/time")
			}
			// Check the correct commits
			for i, got := range call.Arg2 {
				if diff := cmp.Diff(commits[repo][i], got); diff != "" {
					t.Errorf("unexpected commit\n%s", diff)
				}
			}
		}
	}
}

func checkCommits(t *testing.T, want []*gitdomain.Commit, got []*gitdomain.Commit) {
	for i, commit := range got {
		if diff := cmp.Diff(want[i], commit); diff != "" {
			t.Errorf("unexpected commit\n%s", diff)
		}
	}
}

func checkIndexedThough(t *testing.T, want time.Time, got time.Time) {
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("unexpected indexed through date\n%s", diff)
	}
}

// mockIterator generates iterator methods given a list of repo names for test scenarios
func mockIterator(repos []string) func(ctx context.Context, each func(repoName string, id api.RepoID) error) error {
	return func(ctx context.Context, each func(repoName string, id api.RepoID) error) error {
		for i, repo := range repos {
			err := each(repo, api.RepoID(i))
			if err != nil {
				return err
			}
		}
		return nil
	}
}

// commit build a fake commit for test scenarios
func commit(ref string, commitTime string) *gitdomain.Commit {
	t, _ := time.Parse(time.RFC3339, commitTime)

	return &gitdomain.Commit{
		ID:        api.CommitID(ref),
		Committer: &gitdomain.Signature{Date: t},
	}
}

func mockCommits(commits map[string][]*gitdomain.Commit) func(ctx context.Context, db database.DB, name api.RepoName, after time.Time, until *time.Time, operation *observation.Operation) ([]*gitdomain.Commit, error) {
	return func(ctx context.Context, db database.DB, name api.RepoName, after time.Time, until *time.Time, operation *observation.Operation) ([]*gitdomain.Commit, error) {
		filteredCommits := make([]*gitdomain.Commit, 0)
		for _, commit := range commits[string(name)] {
			if commit.Committer.Date.Before(after) {
				continue
			}
			if until != nil && commit.Committer.Date.After(*until) {
				continue
			}
			filteredCommits = append(filteredCommits, commit)
		}
		return filteredCommits, nil
	}
}

func mockCommitsWithError(err error) func(ctx context.Context, db database.DB, name api.RepoName, after time.Time, until *time.Time, operation *observation.Operation) ([]*gitdomain.Commit, error) {
	return func(ctx context.Context, db database.DB, name api.RepoName, after time.Time, until *time.Time, operation *observation.Operation) ([]*gitdomain.Commit, error) {
		return nil, err
	}
}

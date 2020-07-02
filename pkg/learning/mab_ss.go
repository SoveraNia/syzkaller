// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package learning

import (
	"math"
	"math/rand"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// Threshold to filter out bad timing measurements.
const MABSSExecTimeThreshold = 1000000000

type ExecResult struct {
	Coverage int   // Coverage gained.
	TimeExec int64 // Time spent executing program (ns).
}

type MABSeedScheduler struct {
	mu  sync.RWMutex
	mab *MultiArmedBandit

	count        int     // Total number of mutations observed.
	totalCov     int     // Total coverage obtained by mutation.
	totalTime    int64   // Total time cost (ns) by mutation.
	rewardTotal  float64 // Sum of all un-normalized reward.
	rewardTotal2 float64 // Sum of squares of un-normalized reward.

	// Corpus program array. The index in this array is the same as the
	// index in the MAB engine.
	corpus []*prog.Prog
}

func NewMABSeedScheduler(theta float64) *MABSeedScheduler {
	return &MABSeedScheduler{
		mab: &MultiArmedBandit{theta: theta},
	}
}

// Also returns a corpus snapshot to be used in mutation crossovers.
func (ss *MABSeedScheduler) Choose(r *rand.Rand) (int, float64, []*prog.Prog) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	idx, pr := ss.mab.Choose(r)
	if idx < 0 {
		// No choices available in the MAB engine.
		return idx, 0.0, ss.corpus
	}
	corpusSnapshot := ss.corpus
	return idx, pr, corpusSnapshot
}

func (ss *MABSeedScheduler) NewChoice(p *prog.Prog) int {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	idx := ss.mab.NewChoice()
	ss.corpus = append(ss.corpus, p)
	return idx
}

func (ss *MABSeedScheduler) Update(idx int, result ExecResult, pr float64) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	// For executions with bad timing measurements, assume the worst time and
	// don't update totals
	updateTotal := true
	if result.TimeExec <= 0 || result.TimeExec > MABSSExecTimeThreshold {
		result.TimeExec = MABSSExecTimeThreshold
		updateTotal = false
	}

	// Convert coverage and time into a single reward metric.
	var reward float64
	if ss.totalCov != 0 {
		conversionRate := float64(ss.totalTime) / float64(ss.totalCov)
		reward = float64(result.Coverage)*conversionRate - float64(result.TimeExec)
		log.Logf(MABLogLevel, "MAB SS Reward: %v * %v / %v - %v = %v",
			result.Coverage, ss.totalTime,
			ss.totalCov, result.TimeExec,
			reward)
	}
	// Normalization.
	var normReward, mean, std float64
	if ss.count > 0 {
		mean = ss.rewardTotal / float64(ss.count)
		std = (ss.rewardTotal2 / float64(ss.count)) - (mean * mean)
	}
	if std < 0.0 {
		log.Fatalf("error: Cannot compute std sqrt(%v)", std)
	} else if std > 0.0 {
		std = math.Sqrt(std)
		// Normally, Z-score should be z = (reward - meanX) / stdX.
		// However, we want to make sure positive reward is positive.
		// In later stages of fuzzing, meanX is going to be negative.
		// We don't want an "arm" with negative reward be rewarded.
		z := reward / std
		// Prevent overflowing.
		if z > MABExponentThreshold {
			z = MABExponentThreshold
		} else if z < -MABExponentThreshold {
			z = -MABExponentThreshold
		}
		normReward = (1.0 - math.Exp(-z)) / (1.0 + math.Exp(-z))
		log.Logf(1, "MAB SS Normalized Reward: %v; z=%v mean=%v std=%v", normReward, z, mean, std)
	}
	if normReward != 0.0 {
		ss.mab.Update(idx, normReward, pr)
	}
	// Update total time/coverage after everything.
	if updateTotal {
		ss.totalTime += result.TimeExec
		ss.totalCov += result.Coverage
		ss.count++
		ss.rewardTotal += reward
		ss.rewardTotal2 += reward * reward
	}
}

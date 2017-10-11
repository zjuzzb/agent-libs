/*
 * Licensed to Derrick R. Burns under one or more
 * contributor license agreements.  See the NOTICES file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <queue>
#include <utility>
#include <vector>

#ifdef WITH_GLOG

#include "glog/logging.h"

#else // WITH_GLOG

#include "logging.h"

#endif // WITH_GLOG

namespace tdigest {

using Value = double;
using Weight = double;
using Index = size_t;

const size_t kHighWater = 40000;

/////////////////////////////////////////////////////////////////////////

class Centroid {
 public:
  Centroid() = delete;

  Centroid(Value mean, Weight weight = 1) : mean_(mean), weight_(weight)
  {
	CHECK_GT(weight_, 0);
  }

  inline Value mean() const noexcept { return mean_; }

  inline Weight weight() const noexcept { return weight_; }

  inline void add(const Centroid& c) {
    CHECK_GT(c.weight_, 0);
    if( weight_ != 0.0 ) {
      weight_ += c.weight_;
      mean_ += c.weight_ * (c.mean_ - mean_) / weight_;
    } else {
      weight_ = c.weight_;
      mean_ = c.mean_;
    }
  }

 private:
  Value mean_ = 0;
  Weight weight_ = 0;
};

/////////////////////////////////////////////////////////////////////////

struct CentroidList {
  CentroidList(const std::vector<Centroid>& s) : iter(s.cbegin()), end(s.cend()) {}
  std::vector<Centroid>::const_iterator iter;
  std::vector<Centroid>::const_iterator end;

  bool advance() { return ++iter != end; }
};

class CentroidListComparator {
 public:
  CentroidListComparator() {}

  bool operator()(const CentroidList& left, const CentroidList& right) const
  {
    return left.iter->mean() > right.iter->mean();
  }
};

using CentroidListQueue =
  std::priority_queue<CentroidList, std::vector<CentroidList>, CentroidListComparator>;

struct CentroidComparator {
  bool operator()(const Centroid& a, const Centroid& b) const
  {
    return a.mean() < b.mean();
  }
};

/////////////////////////////////////////////////////////////////////////

class TDigest {
  Value compression_;

  // collection of processed/sorted centroids
  std::vector<Centroid> processed_;
  // limit for processed/sorted cntroids
  Index maxProcessed_;
  // sum of weights of processed/sorted centroids
  Value processedWeight_ = 0.0;

  // collection of temporary centroids maintained in the order of addition
  std::vector<Centroid> unprocessed_;
  // limit for temporary cntroids
  Index maxUnprocessed_;
  // sum of weights of temporary centroids
  Value unprocessedWeight_ = 0.0;

  Value min_ = std::numeric_limits<Value>::max();
  Value max_ = std::numeric_limits<Value>::min();

  std::vector<Weight> cumulative_;

  // global settings
  static const bool usePieceWiseApproximation = true;
  static const bool useWeightLimit = true;

  class TDigestComparator {
   public:
    TDigestComparator() {}

    bool operator()(const TDigest* left, const TDigest* right) const { return left->totalSize() > right->totalSize(); }
  };

  using TDigestQueue = std::priority_queue<const TDigest*, std::vector<const TDigest*>, TDigestComparator>;

  static inline
  Index processedSize(Index size, Value compression) noexcept {
    auto ret = (size == 0) ? static_cast<Index>(2 * std::ceil(compression))
                           : size;
    if (useWeightLimit) {
        // the weight limit approach generates smaller centroids than necessary
        // that can result in using a bit more memory than expected
        ret += 10;
    }
    return ret;
  }

  static inline
  Index unprocessedSize(Index size, Value compression) noexcept {
    // having a big buffer is good for speed
    // the java implementation uses a factor of 5 as the default
    return (size == 0) ? static_cast<Index>(5 * std::ceil(compression)) : size;
  }

 public:
  TDigest() : TDigest(1000) {}

  /**
   * Allocates a buffer merging t-digest. This is the normally used
   * constructor that allocates default sized internal arrays. Other
   * versions are available, but should only be used for special cases.
   *
   * @param compression Compression factor for t-digest. Same as 1/\delta in the paper.
   */
  explicit TDigest(Value compression) : TDigest(compression, 0) {}

  /**
   * If you know the size of the temporary buffer for incoming points,
   * you can use this constructor.
   *
   * @param compression Compression factor.
   * @param bufferSize  How many samples to retain before merging/processing.
   */
  TDigest(Value compression, Index bufferSize) : TDigest(compression, bufferSize, 0) {}

  /**
   * Fully specified constructor. Normally only used for deserializing a
   * buffer t-digest.
   *
   * @param compression Compression factor.
   * @param bufferSize  Number of temporary centroids
   * @param size        Size of main buffer
   */
  TDigest(Value compression, Index unmergedSize, Index mergedSize)
      : compression_(compression),
        maxProcessed_(processedSize(mergedSize, compression)),
        maxUnprocessed_(unprocessedSize(unmergedSize, compression)) {
    processed_.reserve(maxProcessed_);
    unprocessed_.reserve(maxUnprocessed_ + 1);
  }

  // copy constructors
  TDigest& operator=(TDigest&& o) {
    compression_ = o.compression_;
    maxProcessed_ = o.maxProcessed_;
    maxUnprocessed_ = o.maxUnprocessed_;
    processedWeight_ = o.processedWeight_;
    unprocessedWeight_ = o.unprocessedWeight_;
    processed_ = std::move(o.processed_);
    unprocessed_ = std::move(o.unprocessed_);
    cumulative_ = std::move(o.cumulative_);
    min_ = o.min_;
    max_ = o.max_;
    return *this;
  }

  TDigest(TDigest&& o)
    : TDigest(std::move(o.processed_), std::move(o.unprocessed_),
              o.compression_, o.maxUnprocessed_, o.maxProcessed_) {}

  // member accessors and misc.
  Value compression() const { return compression_; }

  const std::vector<Centroid>& processed() const { return processed_; }

  const std::vector<Centroid>& unprocessed() const { return unprocessed_; }

  Index maxUnprocessed() const { return maxUnprocessed_; }

  Index maxProcessed() const { return maxProcessed_; }

  Weight processedWeight() const { return processedWeight_; }

  Weight unprocessedWeight() const { return unprocessedWeight_; }

  bool haveUnprocessed() const { return unprocessed_.size() > 0; }

  size_t totalSize() const { return processed_.size() + unprocessed_.size(); }

  long totalWeight() const { return static_cast<long>(processedWeight_ + unprocessedWeight_); }

  /**
   * Clear the contents and reset members to initial state/values
   */
  void clear()
  {
    processed_.clear(); processed_.reserve(maxProcessed_);
    unprocessed_.clear(); unprocessed_.reserve(maxUnprocessed_ + 1);
    cumulative_.clear();

    processedWeight_ = unprocessedWeight_ = 0.0;
    min_ = std::numeric_limits<Value>::max();
    max_ = std::numeric_limits<Value>::min();
  }

  /**
   * Add a sample to tdigest.
   *
   *  @param x	Sample value.
   */
  bool add(Value x) { return add(x, 1); }

  /**
   * Add a sample with given weight to tdigest.
   *
   *  @param x	Sample value.
   *  @param w	Weight of sample.
   */
  inline bool add(Value x, Weight w) {
    if (std::isnan(x)) {
      return false;
    }

    // add a single centroid to the unprocessed vector, processing
    // previously unprocessed sorted if our limit has been reached.
    unprocessed_.push_back(Centroid(x, w));
    unprocessedWeight_ += w;
    processIfNecessary();
    return true;
  }

  /**
   * Merge/add other tdigests.
   *
   * @param digests	Vector of tdigests to be merged/added
   */
  inline
  void add(std::vector<const TDigest*> digests)
  {
    add(digests.cbegin(), digests.cend());
  }

  /**
   * Merge another tdigest.
   *
   * @param other	TDigest to be merged/added
   */
  inline
  void merge(const TDigest* other)
  {
    std::vector<const TDigest*> others{other};
    add(others.cbegin(), others.cend());
  }

  /**
   * Merge a range of tdigest vector in the most efficient manner possible
   * in constant space. Works for any value of kHighWater.
   *
   * @param iter Initial position of the tdigest vector
   * @param end  Final position of the tdigest vector
   */
  void add(std::vector<const TDigest*>::const_iterator iter,
           std::vector<const TDigest*>::const_iterator end)
  {
    if (iter != end) {
      const size_t size = std::distance(iter, end);
      TDigestQueue pq(TDigestComparator{});
      for (; iter != end; iter++) {
        pq.push((*iter));
      }
      std::vector<const TDigest*> batch;
      batch.reserve(size);

      size_t totalSize = 0;
      while (!pq.empty()) {
        auto td = pq.top();
        batch.push_back(td);
        pq.pop();
        totalSize += td->totalSize();
        if (totalSize >= kHighWater || pq.empty()) {
          mergeProcessed(batch);
          mergeUnprocessed(batch);
          processIfNecessary();
          batch.clear();
          totalSize = 0;
        }
      }
      updateCumulative();
    }
  }

  inline void add(std::vector<Centroid>::const_iterator iter,
                  std::vector<Centroid>::const_iterator end) {
    while (iter != end) {
      const size_t diff = std::distance(iter, end);
      const size_t room = maxUnprocessed_ - unprocessed_.size();
      auto mid = iter + std::min(diff, room);
      while (iter != mid) unprocessed_.push_back(*(iter++));
      if (unprocessed_.size() >= maxUnprocessed_) {
        process();
      }
    }
  }

  inline void compress()
  {
    if (! unprocessed_.empty() || isDirty()) {
      process();
    }
  }

  // return the cdf on the t-digest
  Value cdf(Value x)
  {
    if (haveUnprocessed() || isDirty()) process();
    return cdfProcessed(x);
  }

  // return the cdf on the processed values
  Value cdfProcessed(Value x)
  {
    DLOG(INFO) << "cdf value " << x;
    DLOG(INFO) << "processed size " << processed_.size();
    if (processed_.size() == 0) {
      // no data to examine
      DLOG(INFO) << "no processed values";

      return NAN;
    } else if (processed_.size() == 1) {
      DLOG(INFO) << "one processed value "
                 << " min_ " << min_ << " max_ " << max_;
      // exactly one centroid, should have max_==min_
      auto width = max_ - min_;
      if (x < min_) {
        return 0.0;
      } else if (x > max_) {
        return 1.0;
      } else if (x - min_ <= width) {
        // min_ and max_ are too close together to do any viable interpolation
        return 0.5;
      } else {
        // interpolate if somehow we have weight > 0 and max_ != min_
        return (x - min_) / (max_ - min_);
      }
    } else {
      auto n = processed_.size();
      if (x <= min_) {
        DLOG(INFO) << "below min_ "
                   << " min_ " << min_ << " x " << x;
        return 0;
      }

      if (x >= max_) {
        DLOG(INFO) << "above max_ "
                   << " max_ " << max_ << " x " << x;
        return 1;
      }

      // check for the left tail
      if (x <= mean(0)) {
        DLOG(INFO) << "left tail "
                   << " min_ " << min_ << " mean(0) " << mean(0) << " x " << x;

        // note that this is different than mean(0) > min_ ... this guarantees interpolation works
        if (mean(0) - min_ > 0) {
          return (x - min_) / (mean(0) - min_) * weight(0) / processedWeight_ / 2.0;
        } else {
          return 0;
        }
      }
      //CHECK_GT(x, mean(0));

      // and the right tail
      if (x >= mean(n - 1)) {
        DLOG(INFO) << "right tail"
                   << " max_ " << max_ << " mean(n - 1) " << mean(n - 1) << " x " << x;

        if (max_ - mean(n - 1) > 0) {
          return 1.0 - (max_ - x) / (max_ - mean(n - 1)) * weight(n - 1) / processedWeight_ / 2.0;
        } else {
          return 1;
        }
      }

      if (cumulative_.empty()) {
        updateCumulative();
      }

      // we know that there are at least two centroids and
      // x > mean[0] && x < mean[n-1]
      // that means that there are either a bunch of consecutive centroids
      // all equal at x or there are consecutive centroids, c0 <= x and c1 > x

      // obtain the centroid whose mean is equal/greater than x
      CentroidComparator cc;
      auto iter = std::lower_bound(processed_.cbegin(), processed_.cend(), Centroid(x), cc);
      size_t i = std::distance(processed_.cbegin(), iter);
      if (mean(i) == x && mean(i+1) == x) {
        auto w0 = cumulative_[i];
        auto weightSoFar = w0;
        for (; i < n && mean(i+1) == x; ++i) {
          weightSoFar += weight(i) + weight(i+1);
        }
        return (w0 + weightSoFar) / 2 / processedWeight_;
      }
      if (mean(i) == x) ++i;
      CHECK_GT(mean(i), x);
      auto diff = mean(i) - mean(i-1);
      if (diff > 0) {
        return (cumulative_[i-1] + cumulative_[i] * (x - mean(i-1)) / diff) / processedWeight_;
      } else {
        // this is simply caution against floating point madness
        // it is conceivable that the centroids will be different
        // but too near to allow safe interpolation
        return cumulative_[i-1] + cumulative_[i] / processedWeight_;
      }
    }
  }

  // this returns a quantile on the t-digest
  Value quantile(Value q)
  {
    if (haveUnprocessed() || isDirty()) process();
    return quantileProcessed(q);
  }

  // this returns a quantile on the currently processed values without changing the t-digest
  // the value will not represent the unprocessed values
  Value quantileProcessed(Value q)
  {
    if (q < 0 || q > 1) {
      LOG(ERROR) << "q should be in [0,1], got " << q;
      return NAN;
    }

    if (processed_.size() == 0) {
      // no sorted means no data, no way to get a quantile
      return NAN;
    } else if (processed_.size() == 1) {
      // with one data point, all quantiles lead to Rome
      return mean(0);
    }

    // we know that there are at least two sorted now
    auto n = processed_.size();

    // if values were stored in a sorted array, index would be the offset we are interested in
    const auto index = q * processedWeight_;

    // at the boundaries, we return min_ or max_
    if (index < weight(0) / 2.0) {
      CHECK_GT(weight(0), 0);
      return min_ + 2.0 * index / weight(0) * (mean(0) - min_);
    }

    if (cumulative_.empty()) {
      updateCumulative();
    }
    auto iter = std::upper_bound(cumulative_.cbegin(), cumulative_.cend(), index);
    const size_t i = std::distance(cumulative_.cbegin(), iter);
    if (i < n) {
      // centroids i-1 and i bracket our current point
      auto z1 = index - *(iter-1);
      auto z2 = *(iter) - index;
      return weightedAverage(mean(i-1), z2, mean(i), z1);
    }

    CHECK_LE(index, processedWeight_);
    CHECK_GE(index, processedWeight_ - weight(n - 1) / 2.0);

    // weightSoFar = totalWeight - weight[n-1]/2 (very nearly)
    // so we interpolate out to max value ever seen
    auto z1 = index - processedWeight_ - weight(n - 1) / 2.0;
    auto z2 = weight(n - 1) / 2 - z1;
    return weightedAverage(mean(n - 1), z1, max_, z2);
  }

 private:
  static Weight weight(std::vector<Centroid>& centroids) noexcept {
    Weight w = 0.0;
    for (auto centroid : centroids) {
      w += centroid.weight();
    }
    return w;
  }

  static void validate(const std::vector<Centroid> &vec)
  {
    (void)(vec);
#if !defined(NDEBUG) || defined(DEBUG)
    for (auto &c: vec) {
      CHECK_GT(c.weight(), 0);
    }
#endif
  }

  TDigest(std::vector<Centroid>&& processed,
          std::vector<Centroid>&& unprocessed, Value compression,
          Index unmergedSize, Index mergedSize)
      : TDigest(compression, unmergedSize, mergedSize) {
    processed_ = std::move(processed);
    unprocessed_ = std::move(unprocessed);

    processedWeight_ = weight(processed_);
    unprocessedWeight_ = weight(unprocessed_);
    if (processed_.size() > 0) {
      min_ = std::min(min_, processed_.front().mean());
      max_ = std::max(max_, processed_.back().mean());
    }
    updateCumulative();
  }

  bool isDirty() { return processed_.size() > maxProcessed_ || unprocessed_.size() > maxUnprocessed_; }

  // return mean of i-th centroid
  inline Value mean(int i) const noexcept { return processed_[i].mean(); }

  // return weight of i-th centroid
  inline Weight weight(int i) const noexcept { return processed_[i].weight(); }

  // append all unprocessed centroids into current unprocessed vector
  void mergeUnprocessed(const std::vector<const TDigest*>& tdigests) {
    if (tdigests.size() == 0) return;

    size_t total = unprocessed_.size();
    for (auto& td : tdigests) {
      total += td->unprocessed_.size();
    }

    unprocessed_.reserve(total);
    for (auto& td : tdigests) {
      validate(td->unprocessed_);

      unprocessed_.insert(unprocessed_.end(), td->unprocessed_.cbegin(), td->unprocessed_.cend());
      unprocessedWeight_ += td->unprocessedWeight_;
    }
  }

  // merge all processed centroids together into a single sorted vector
  void mergeProcessed(const std::vector<const TDigest*>& tdigests) {
    if (tdigests.size() == 0) return;

    size_t total = 0;
    CentroidListQueue pq(CentroidListComparator{});
    for (auto& td : tdigests) {
      auto& sorted = td->processed_;
      auto size = sorted.size();
      if (size > 0) {
        pq.push(CentroidList(sorted));
        total += size;
        processedWeight_ += td->processedWeight_;
      }
    }
    if (total == 0) return;

    if (processed_.size() > 0) {
      pq.push(CentroidList(processed_));
      total += processed_.size();
    }

    std::vector<Centroid> sorted;
    LOG(INFO) << "total " << total;
    sorted.reserve(total);

    while (!pq.empty()) {
      auto best = pq.top();
      pq.pop();
      sorted.push_back(*(best.iter));
      if (best.advance()) pq.push(best);
    }
    processed_ = std::move(sorted);
    if( processed_.size() > 0 ) {
      min_ = std::min(min_, processed_.front().mean());
      max_ = std::max(max_, processed_.back().mean());
    }
    validate(processed_);
  }

  inline void processIfNecessary() {
    if (isDirty()) {
      process();
    }
  }

  void updateCumulative() {
    const auto n = processed_.size();
    cumulative_.clear();
    cumulative_.reserve(n + 1);
    auto previous = 0.0;
    for (Index i = 0; i < n; i++) {
      auto current = weight(i);
      auto halfCurrent = current / 2.0;
      cumulative_.push_back(previous + halfCurrent);
      previous = previous + current;
    }
    cumulative_.push_back(previous);
  }

  // merges unprocessed_ centroids and processed_ centroids together and processes them
  // when complete, unprocessed_ will be empty and processed_ will have at most maxProcessed_ centroids
  inline void process() {
    CentroidComparator cc;
    std::sort(unprocessed_.begin(), unprocessed_.end(), cc);
    auto count = unprocessed_.size();
    unprocessed_.insert(unprocessed_.end(), processed_.cbegin(), processed_.cend());
    std::inplace_merge(unprocessed_.begin(), unprocessed_.begin() + count, unprocessed_.end(), cc);

    CHECK_GT(unprocessed_.size(), 0);
    validate(unprocessed_);

    processedWeight_ += unprocessedWeight_;
    unprocessedWeight_ = 0;
    processed_.clear(); processed_.reserve(maxProcessed_);
    const auto normalizer = compression_ / (M_PI * processedWeight_);

    processed_.push_back(unprocessed_[0]);
    Weight wSoFar = 0;
    Weight wLimit = processedWeight_ * integratedQ(1.0);

    auto end = unprocessed_.cend();
    for (auto iter = unprocessed_.cbegin() + 1; iter < end; iter++) {
      auto& centroid = *iter;
      auto &lastProcessedCentroid(processed_.back());
      Weight proposedW = lastProcessedCentroid.weight() + centroid.weight();
      Weight projectedW = wSoFar + proposedW;
      bool addThis = false;
      if (useWeightLimit) {
        auto z  = proposedW * normalizer;
        auto q0 = wSoFar / processedWeight_;
        auto q2 = (wSoFar + proposedW) / processedWeight_;
        addThis = ((z * z) <= (q0 * (1 - q0))) && ((z * z) <= (q2 * (1 - q2)));
      } else {
        addThis = (projectedW <= wLimit);
      }
      if (addThis) {
        // next point will fit - so merge into existing centroid
        lastProcessedCentroid.add(centroid);
      } else {
        // didn't fit ... move to next output, copy out centroid
        wSoFar += lastProcessedCentroid.weight();
        if (!useWeightLimit) {
          auto k1 = integratedLocation(wSoFar / processedWeight_);
          wLimit = processedWeight_ * integratedQ(k1 + 1.0);
        }

        processed_.emplace_back(centroid);
      }
    }
    validate(processed_);
    unprocessed_.clear(); unprocessed_.reserve(maxUnprocessed_ + 1);
    min_ = std::min(min_, processed_.front().mean());
    max_ = std::max(max_, processed_.back().mean());
    DLOG(INFO) << "new min_ " << min_;
    DLOG(INFO) << "new max_ " << max_;
    cumulative_.clear();
  }

  inline int checkWeights() { return checkWeights(processed_, processedWeight_); }

  size_t checkWeights(const std::vector<Centroid>& sorted, Value total)
  {
    size_t badWeight = 0;
    auto k1 = 0.0;
    auto q = 0.0;
    auto left = 0.0;
    size_t dist = 0;
    for (const auto &centroid : sorted) {
      auto w = centroid.weight();
      auto dq = w / total;
      auto k2 = integratedLocation(q + dq);
      q += dq/2;
      auto maxW = M_PI*total / compression_ * std::sqrt(q*(1-q));
      if (k2 - k1 > 1 && w != 1) {
        LOG(WARNING) << "Oversize centroid at " << dist
          << " k1:" << k1 << " k2:" << k2 << " dk:" << (k2 - k1)
          << " w:" << w << " q:" << q << " dq:" << dq << " left:" << left
          << " maxW:" << maxW;
        badWeight++;
      }
      if (k2 - k1 > 4 && w != 1) {
        LOG(ERROR) << "Egregiously Oversize centroid at " << dist
          << " k1:" << k1 << " k2:" << k2 << " dk:" << (k2 - k1)
          << " w:" << w << " q:" << q << " dq:" << dq << " left:" << left
          << " maxW:" << maxW;
        badWeight++;
      }
      q += dq/2;
      left += w;
      k1 = k2;
      ++dist;
    }

    return badWeight;
  }

  /**
   * Converts a quantile into a centroid scale value.  The centroid scale is nominally
   * the number k of the centroid that a quantile point q should belong to.  Due to
   * round-offs, however, we can't align things perfectly without splitting points
   * and centroids.  We don't want to do that, so we have to allow for offsets.
   * In the end, the criterion is that any quantile range that spans a centroid
   * scale range more than one should be split across more than one centroid if
   * possible.  This won't be possible if the quantile range refers to a single point
   * or an already existing centroid.
   *
   * This mapping is steep near q=0 or q=1 so each centroid there will correspond to
   * less q range.  Near q=0.5, the mapping is flatter so that centroids there will
   * represent a larger chunk of quantiles.
   *
   * @param q The quantile scale value to be mapped.
   * @return The centroid scale value corresponding to q.
   */
  inline Value integratedLocation(Value q) const
  {
    return compression_ * (asinApproximation(2.0 * q - 1.0) + M_PI / 2) / M_PI;
  }

  inline Value integratedQ(Value k) const
  {
    return (std::sin(std::min(k, compression_) * M_PI / compression_ - M_PI / 2) + 1) / 2;
  }

  static
  Value eval(const std::vector<double> &model,
             const std::vector<double> &vars)
  {
    Value r = 0;
    for (size_t i = 0; i < model.size(); i++) {
      r += model[i] * vars[i];
    }
    return r;
  }

  static
  Value bound(Value v) {
    return (v <= 0) ? 0 :
           (v >= 1) ? 1 : v;
  }

  static
  Value asinApproximation(Value x)
  {
    if (!usePieceWiseApproximation) {
      return std::asin(x);
    } else {
      if (x < 0) {
        return -asinApproximation(-x);
      } else {
        // this approximation works by breaking that range from 0 to 1 into 5 regions
        // for all but the region nearest 1, rational polynomial models get us a very
        // good approximation of asin and by interpolating as we move from region to
        // region, we can guarantee continuity and we happen to get monotonicity as well.
        // for the values near 1, we just use Math.asin as our region "approximation".

        // cutoffs for models. Note that the ranges overlap. In the overlap we do
        // linear interpolation to guarantee the overall result is "nice"
        const double c0High = 0.1;
        const double c1High = 0.55;
        const double c2Low = 0.5;
        const double c2High = 0.8;
        const double c3Low = 0.75;
        const double c3High = 0.9;
        const double c4Low = 0.87;
        if (x > c3High) {
          return std::asin(x);
        } else {
          // the models
          using dVec = const std::vector<double>;
          static dVec m0 = {0.2955302411   , 1.2221903614  , 0.1488583743   , 0.2422015816  , -0.3688700895 , 0.0733398445   };
          static dVec m1 = {-0.0430991920  , 0.9594035750  , -0.0362312299  , 0.1204623351  , 0.0457029620  , -0.0026025285  };
          static dVec m2 = {-0.034873933724, 1.054796752703, -0.194127063385, 0.283963735636, 0.023800124916, -0.000872727381};
          static dVec m3 = {-0.37588391875 , 2.61991859025 , -2.48835406886 , 1.48605387425 , 0.00857627492 , -0.00015802871 };

          // the parameters for all of the models
          dVec vars = {1, x, x * x, x * x * x, 1 / (1 - x), 1 / (1 - x) / (1 - x)};

          // raw grist for interpolation coefficients
          auto x0 = bound((c0High - x) / c0High);
          auto x1 = bound((c1High - x) / (c1High - c2Low));
          auto x2 = bound((c2High - x) / (c2High - c3Low));
          auto x3 = bound((c3High - x) / (c3High - c4Low));

          // interpolation coefficients
          //noinspection UnnecessaryLocalVariable
          auto mix0 = x0;
          auto mix1 = (1 - x0) * x1;
          auto mix2 = (1 - x1) * x2;
          auto mix3 = (1 - x2) * x3;
          auto mix4 = 1 - x3;

          // now mix all the results together, avoiding extra evaluations
          double r = 0;
          if (mix0 > 0) {
            r += mix0 * eval(m0, vars);
          }
          if (mix1 > 0) {
            r += mix1 * eval(m1, vars);
          }
          if (mix2 > 0) {
            r += mix2 * eval(m2, vars);
          }
          if (mix3 > 0) {
            r += mix3 * eval(m3, vars);
          }
          if (mix4 > 0) {
            // model 4 is just the real deal
            r += mix4 * std::asin(x);
          }
          return r;
        }
      } // x >= 0
    } // usePieceWiseApproximation == true
  }

  /**
   * Same as {@link #weightedAverageSorted(Value, Value, Value, Value)} but flips
   * the order of the variables if <code>x2</code> is greater than
   * <code>x1</code>.
   */
  static
  Value weightedAverage(Value x1, Value w1, Value x2, Value w2)
  {
    return (x1 <= x2) ? weightedAverageSorted(x1, w1, x2, w2)
                      : weightedAverageSorted(x2, w2, x1, w1);
  }

  /**
   * Compute the weighted average between <code>x1</code> with a weight of
   * <code>w1</code> and <code>x2</code> with a weight of <code>w2</code>.
   * This expects <code>x1</code> to be less than or equal to <code>x2</code>
   * and is guaranteed to return a number between <code>x1</code> and
   * <code>x2</code>.
   */
  static
  Value weightedAverageSorted(Value x1, Value w1, Value x2, Value w2)
  {
    CHECK_LE(x1, x2);
    const Value x = (x1 * w1 + x2 * w2) / (w1 + w2);
    return std::max(x1, std::min(x, x2));
  }

  static
  Value interpolate(Value x, Value x0, Value x1)
  {
    return (x - x0) / (x1 - x0);
  }

  /**
   * Computes an interpolated value of a quantile that is between two sorted.
   *
   * Index is the quantile desired multiplied by the total number of samples - 1.
   *
   * @param index              Denormalized quantile desired
   * @param previousIndex      The denormalized quantile corresponding to the center of the previous centroid.
   * @param nextIndex          The denormalized quantile corresponding to the center of the following centroid.
   * @param previousMean       The mean of the previous centroid.
   * @param nextMean           The mean of the following centroid.
   * @return  The interpolated mean.
   */
  static
  Value quantile(Value index, Value previousIndex, Value nextIndex,
                 Value previousMean, Value nextMean)
  {
    const auto delta = nextIndex - previousIndex;
    const auto previousWeight = (nextIndex - index) / delta;
    const auto nextWeight = (index - previousIndex) / delta;
    return previousMean * previousWeight + nextMean * nextWeight;
  }
};

}  // namespace tdigest

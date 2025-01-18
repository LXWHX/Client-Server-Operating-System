// http://www.cplusplus.com/reference/ctime/time/ is helpful here
#include <deque>
#include <iostream>
#include <memory>

#include "quota_tracker.h"

using namespace std;

/// quota_tracker stores time-ordered information about events.  It can count
/// events within a pre-set, fixed time threshold, to decide if a new event can
/// be allowed without violating a quota.
class my_quota_tracker : public quota_tracker {

private:
//The maximum amount of service
size_t aAmount; 
//The time over which the service maximum can be spread out
double dDuration; 
//tracker queue(time check, size check)
std::deque<std::pair<time_t, size_t> > trackqueue;

public:
  /// Construct a tracker that limits usage to quota_amount per quota_duration
  /// seconds
  ///
  /// @param amount   The maximum amount of service
  /// @param duration The time over which the service maximum can be spread out
  my_quota_tracker(size_t amount, double duration) {
    dDuration = duration;
    aAmount = amount;
  }

  /// Destruct a quota tracker
  virtual ~my_quota_tracker() {}

  /// Decide if a new event is permitted, and if so, add it.  The attempt is
  /// allowed if it could be added to events, while ensuring that the sum of
  /// amounts for all events within the duration is less than q_amnt.
  ///
  /// @param amount The amount of the new request
  ///
  /// @return false if the amount could not be added without violating the
  ///         quota, true if the amount was added while preserving the quota
  virtual bool check_add(size_t amount) {
    //get current time
    time_t currentT; 
    time(&currentT);
    //get current request amount
    size_t currentA = amount; 
    //iter through the queue
    for (auto it = trackqueue.begin(); it < trackqueue.end(); ++it) {
      //check time
      if ((*it).first >= (currentT - dDuration)) {
        //add task
        currentA += (*it).second;
        //if exceed the max # of request
        if (currentA > aAmount) {
          return false; 
        }

      }
      else{
        break; 
      } 
    }
    //push the new added to event tracker
    trackqueue.push_front(std::make_pair(time(NULL), amount));

    return true; 
  }
};

/// Construct a tracker that limits usage to quota_amount per quota_duration
/// seconds
///
/// @param amount   The maximum amount of service
/// @param duration The time over which the service maximum can be spread out
quota_tracker *quota_factory(size_t amount, double duration) {
  return new my_quota_tracker(amount, duration);
}
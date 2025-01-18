#include <deque>
#include <iostream>
#include <mutex>

#include "mru.h"

using namespace std;

/// my_mru maintains a listing of the K most recent elements that have been
/// given to it.  It can be used to produce a "top" listing of the most recently
/// accessed keys.
class my_mru : public mru_manager {

private:
//create dequeue
deque<string> mrudq;
size_t maxsize;
mutex mutexlock;

public:
  /// Construct the mru_manager by specifying how many things it should track
  ///
  /// @param elements The number of elements that can be tracked
  my_mru(size_t elements) {
    //keep track of the max #of element
    maxsize=elements;
  }

  /// Destruct the mru_manager
  virtual ~my_mru() {}

  /// Insert an element into the mru_manager, making sure that (a) there are no
  /// duplicates, and (b) the manager holds no more than /max_size/ elements.
  ///
  /// @param elt The element to insert
  virtual void insert(const std::string &elt) {
    //use remove to ensure there is no duplicate
    remove(elt); 
    
    mutexlock.lock();

    // remove if full
    if (mrudq.size() >= maxsize) {
      mrudq.pop_front();
    }
    // add element
    mrudq.push_back(elt);
      
    mutexlock.unlock();
  }

  /// Remove an instance of an element from the mru_manager.  This can leave the
  /// manager in a state where it has fewer than max_size elements in it.
  ///
  /// @param elt The element to remove
  virtual void remove(const std::string &elt) {
    mutexlock.lock();
    for (size_t i = 0; i < mrudq.size(); i++) {
      if (mrudq[i].compare(elt) == 0)
        mrudq.erase(mrudq.begin() + i);
    }
    mutexlock.unlock();
  }

  /// Clear the mru_manager
  virtual void clear() {
    mutexlock.lock();
    mrudq.clear();
    mutexlock.unlock();
  }

  /// Produce a concatenation of the top entries, in order of popularity
  ///
  /// @return A newline-separated list of values
  virtual std::string get() {
    mutexlock.lock();
    string getStrings;
    for (auto iter : mrudq) {
      //add newlines
      getStrings.insert(getStrings.begin(), '\n'); 
      //insert
      getStrings.insert(getStrings.begin(), iter.begin(), iter.end());
    }
    mutexlock.unlock();
    return getStrings; 
  }
};

/// Construct the mru_manager by specifying how many things it should track
///
/// @param elements The number of elements that can be tracked in MRU fashion
///
/// @return An mru manager object
mru_manager *mru_factory(size_t elements) { return new my_mru(elements); }
#include <atomic>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <queue>
#include <thread>
#include <unistd.h>

#include "pool.h"

using namespace std;

class my_pool : public thread_pool {
  // Hint: the reference solution uses an atomic variable, a queue, a mutex, a
  // condition variable, two function pointers, and a vector.  You probably
  // can't implement a pool with less.

  // Hint: you might want to add additional private methods to this class.  For
  // example, in the reference solution, one of the methods of this class is the
  // function that each thread runs.
private: 
  //syncornize the thread
  condition_variable conditionVar;
  //vec for all threads
  vector<thread> threads;
  //secure thread safe
  mutex mutlock;
  //waitlist for client socket
  queue<int> waitlist;
  //used in set_shutdown_handler
  function<void()> shutdown;
  //indicate the thread pool is stooped or not
  atomic_bool stopped = false;

public:
  /// construct a thread pool by providing a size and the function to run on
  /// each element that arrives in the queue
  ///
  /// @param size    The number of threads in the pool
  /// @param handler The code to run whenever something arrives in the pool
  my_pool(int size, function<bool(int)> handler) {
    //initialize threads
    for (auto i = 0; i < size; ++i) {
      threads.emplace_back([this, handler] {
        //check for safety
        while (!stopped.load()) {
          //socket descriptor
          int socketdescript;
          {
            //secure for waitlist
            unique_lock<mutex> lock(mutlock);
            conditionVar.wait(lock, [this] {return !waitlist.empty() || stopped.load();});
            //check immidiate after current task
            if (stopped.load()) {
              break;
            }
            socketdescript = waitlist.front();
            waitlist.pop();
          }
          //check to close thread
          bool shouldshutdown = handler(socketdescript);
          //close connection and release resource
          close(socketdescript);
          //close thread by sett stopped to true.
          if (shouldshutdown) {
            shutdown();
            stopped.store(true);//same as =
            break;
          }
        }});
    }
  }

  /// destruct a thread pool
  ///
  /// Hint: If you do things right, you probably won't need to write a
  /// destructor
  virtual ~my_pool() = default;

  /// Allow a user of the pool to provide some code to run when the pool decides
  /// it needs to shut down.
  ///
  /// @param func The code that should be run when the pool shuts down
  virtual void set_shutdown_handler(function<void()> func) {
    // Hint: You probably just need to save the function for later.
    shutdown = func;
  }

  /// Allow a user of the pool to see if the pool has been shut down
  virtual bool check_active() {
    //return false;
    bool checkactive = !stopped;
    return checkactive;
  }

  /// Shutting down the pool can take some time.  await_shutdown() lets a user
  /// of the pool wait until the threads are all done servicing clients.
  virtual void await_shutdown() {
    //notify other thread to check stopped's value
    conditionVar.notify_all();
    for(auto &t : threads){
      //wait for all thread to finish?

      t.join();
    }
    // clear threads
    threads.clear(); 
  }

  /// When a new connection arrives at the server, it calls this to pass the
  /// connection to the pool for processing.
  ///
  /// @param sd The socket descriptor for the new connection
  virtual void service_connection(int sd) {
    {
      unique_lock<mutex> lock(mutlock); 
      //add new user to waitlist
      waitlist.push(sd); 
    } 
    //give to a thread
    conditionVar.notify_one(); 
  }
};

/// Create a thread_pool object.
///
/// We use a factory pattern (with private constructor) to ensure that anyone
thread_pool *pool_factory(int size, function<bool(int)> handler) {
  // Hint: Don't change this function!
  return new my_pool(size, handler);
}

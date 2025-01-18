#include <functional>
#include <iostream>
#include <list>
#include <mutex>
#include <string>
#include <vector>

#include "map.h"

/// ConcurrentMap is a concurrent implementation of the Map interface (a
/// Key/Value store).  It is implemented as a vector of buckets, with one lock
/// per bucket.  Since the number of buckets is fixed, performance can suffer if
/// the thread count is high relative to the number of buckets.  Furthermore,
/// the asymptotic guarantees of this data structure are dependent on the
/// quality of the bucket implementation.  If a vector is used within the bucket
/// to store key/value pairs, then the guarantees will be poor if the key range
/// is large relative to the number of buckets.  If an unordered_map is used,
/// then the asymptotic guarantees should be strong.
///
/// The ConcurrentMap is templated on the Key and Value types.
///
/// This map uses std::hash to map keys to positions in the vector.  A
/// production map should use something better.
///
/// This map provides strong consistency guarantees: every operation uses
/// two-phase locking (2PL), and the lambda parameters to methods enable nesting
/// of 2PL operations across maps.
///
/// @tparam K The type of the keys in this map
/// @tparam V The type of the values in this map
template <typename K, typename V> class ConcurrentMap : public Map<K, V> {
  // Hint: The reference solution uses a vector of structs, where the struct
  // combines a mutex with a collection.  It also has a field for the number of
  // buckets.  You should think carefully about whether your vector should hold
  // those structs directly, or hold pointers to those structs.  Your decision
  // will determine if you need a real destructor or not.
private:
  //total buckets
  size_t totalbuk;

public:
  //a vector of buckets, with one lock per bucket
  struct Bucket { 
    std::list<std::pair<K,V>> bucketdata;
    std::mutex bucketlock; 
  };
  std::vector<Bucket*> vecofbucket; 

  /// Construct by specifying the number of buckets it should have
  ///
  /// @param _buckets The number of buckets
  ConcurrentMap(size_t _buckets) {
    totalbuk = _buckets;
    for (size_t i=0; i<_buckets; i++) {
      vecofbucket.push_back(new Bucket());
    }
  }

  /// Destruct the ConcurrentMap
  virtual ~ConcurrentMap() {
    for (auto &bucket : vecofbucket) {
      delete bucket;
    }
  }

  /// Clear the map.  This operation needs to use 2pl
  virtual void clear() {
    //2 pahse locking to clear
    for(auto &cl : vecofbucket){
      cl->bucketlock.lock();
      cl->bucketdata.clear();      
    }
    //unlock all locks
    for (auto &cl : vecofbucket) {
      if (!cl->bucketlock.try_lock()) {
        cl->bucketlock.unlock();
      }
    }
  }

  /// Insert the provided key/value pair only if there is no mapping for the key
  /// yet.
  ///
  /// @param key        The key to insert
  /// @param val        The value to insert
  ///
  /// @return true if the key/value was inserted, false if the key already
  ///         existed in the table
  virtual bool insert(K key, V val) {
    //hash the key
    std::hash<K> hashkey;
    //calculate index of bucket
    std::size_t hashedKey = hashkey(key) % totalbuk;
    // pass the indexed bucket to this pointer
    auto &indexedbucket = vecofbucket[hashedKey];
    //security lock indexed data
    std::lock_guard<std::mutex> lock(indexedbucket->bucketlock);
    //search to find same k/v pair
    for (auto &i : indexedbucket->bucketdata) {
      if (i.first == key) {
        return false;
      }
    }
    //newdata
    indexedbucket->bucketdata.push_back(std::make_pair(key, val)); 

    return true;
  }

  /// Insert the provided key/value pair if there is no mapping for the key yet.
  /// If there is a key, then update the mapping by replacing the old value with
  /// the provided value
  ///
  /// @param key    The key to upsert
  /// @param val    The value to upsert
  ///
  /// @return true if the key/value was inserted, false if the key already
  ///         existed in the table and was thus updated instead
  virtual bool upsert(K key, V val) {
    // std::cout << "ConcurrentHashMap::upsert() is not implemented";
    //hash the key
    std::hash<K> hashkey;
    //calculate index of bucket
    std::size_t hashedKey = hashkey(key) % totalbuk;
    // pass the indexed bucket to this pointer
    auto &indexedbucket = vecofbucket[hashedKey];
    //security lock indexed data
    std::lock_guard<std::mutex> lock(indexedbucket->bucketlock);
    //search to find same k/v pair then change it
    for (auto &i : indexedbucket->bucketdata) {
      if (i.first == key) {
        i.second = val;

        return false; 
      }
    }
    //new data
    indexedbucket->bucketdata.push_back(std::make_pair(key, val)); 
    return true;
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @return true if the key existed and the function was applied, false
  ///         otherwise
  virtual bool do_with(K key, std::function<void(V &)> f) {
    //hash the key
    std::hash<K> hashkey;
    //calculate index of bucket
    std::size_t hashedKey = hashkey(key) % totalbuk;
    // pass the indexed bucket to this pointer
    auto &indexedbucket = vecofbucket[hashedKey];
    //security lock indexed data
    std::lock_guard<std::mutex> lock(indexedbucket->bucketlock);
    for (auto &i : indexedbucket->bucketdata) {
      if (i.first == key) {
        //run function f
        f(i.second);
        return true;
      }
    }
    //key is not found
    return false;
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is not allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @return true if the key existed and the function was applied, false
  ///         otherwise
  virtual bool do_with_readonly(K key, std::function<void(const V &)> f) {
    //hash the key
    std::hash<K> hashkey;
    //calculate index of bucket
    std::size_t hashedKey = hashkey(key) % totalbuk;
    // pass the indexed bucket to this pointer
    auto &indexedbucket = vecofbucket[hashedKey];
    //security lock indexed data
    std::lock_guard<std::mutex> lock(indexedbucket->bucketlock);

    for (auto &i : indexedbucket->bucketdata) {
      if (i.first == key) {
        //it has const V above, but give this another layer of protection!!
        V copyval = i.second;
        f(copyval);
        return true;
      }
    }
    //key is not found
    return false;
  }

  /// Remove the mapping from a key to its value
  ///
  /// @param key        The key whose mapping should be removed
  ///
  /// @return true if the key was found and the value unmapped, false otherwise
  virtual bool remove(K key) {
    //hash the key
    std::hash<K> hashkey;
    //calculate index of bucket
    std::size_t hashedKey = hashkey(key) % totalbuk;
    // pass the indexed bucket to this pointer
    auto &indexedbucket = vecofbucket[hashedKey];
    //security lock indexed data
    std::lock_guard<std::mutex> lock(indexedbucket->bucketlock);
    //iteration
    for (auto i = indexedbucket->bucketdata.begin(); i != indexedbucket->bucketdata.end(); i++) {
      //finding the k/v pair
      if (i->first == key) {
        //remove data
        indexedbucket->bucketdata.erase(i); 
        return true;
      }
    }
    //key is not found
    return false; 
  }

  /// Apply a function to every key/value pair in the map.  Note that the
  /// function is not allowed to modify keys or values.
  ///
  /// @param f    The function to apply to each key/value pair
  /// @param then A function to run when this is done, but before unlocking...
  ///             useful for 2pl
  virtual void do_all_readonly(std::function<void(const K, const V &)> f,
                               std::function<void()> then) {
    //implement 2phase lock
  for(auto &cl : vecofbucket){
        cl->bucketlock.lock();
        for(auto &i : cl->bucketdata){
          K keycopy = i.first;
          V valcopy = i.second;
          //function to run with read only
          f(keycopy,valcopy);
        }
  }
  //run before unlock
  then();
  // unlock all lock
  for(auto &cl : vecofbucket){
    cl->bucketlock.unlock();      
  }
  }
};

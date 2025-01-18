#include <string>
#include <vector>

#include "authtableentry.h"
#include "concurrentmap.h"

using namespace std;

/// Create an instance of ConcurrentMap that can be used as an authentication
/// table
///
/// @param _buckets The number of buckets in the table
Map<string, AuthTableEntry> *authtable_factory(size_t _buckets) {
  return new ConcurrentMap<string, AuthTableEntry>(_buckets);
}

/// Create an instance of ConcurrentMap that can be used as a key/value store
///
/// @param _buckets The number of buckets in the table
Map<string, vector<uint8_t>> *kvstore_factory(size_t _buckets) {
  return new ConcurrentMap<string, vector<uint8_t>>(_buckets);
}
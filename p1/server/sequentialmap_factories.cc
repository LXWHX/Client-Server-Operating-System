#include <string>
#include <vector>

#include "authtableentry.h"
#include "sequentialmap.h"

using namespace std;

/// Create an instance of SequentialMap that can be used as an authentication
/// table
///
/// NB: This is required only because we're hiding the implementation of the
///     map.
///
/// @param  buckets The number of buckets in the table
Map<string, AuthTableEntry> *authtable_factory(size_t buckets) {
  return new SequentialMap<string, AuthTableEntry>(buckets);
}

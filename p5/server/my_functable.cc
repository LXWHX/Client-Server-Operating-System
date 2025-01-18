#include <atomic>
#include <dlfcn.h>
#include <iostream>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../common/constants.h"
#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/file.h"

#include "functable.h"
#include "functypes.h"

using namespace std;

/// func_table is a table that stores functions that have been registered with
/// our server, so that they can be invoked by clients on the key/value pairs in
/// kv_store.
class my_functable : public FuncTable {
  // TODO: You probably need some fields :)
  shared_mutex mutexx;
  //map to store functions
  unordered_map< string, pair<map_func, reduce_func> > funcmap;
  //store list of .so file location and handlers
  vector<string> files;
  vector<void *> handlers;
public:
  /// Construct a function table for storing registered functions
  my_functable() {
    // TODO: You may need to implement this?
  }

  /// Destruct a function table
  virtual ~my_functable() {
    // TODO: You may need to implement this?
    shutdown();
  }


  // Helper function to write .so file from bytes
  //
  /// @param mrname The name to associate with the functions
  /// @param so     The so contents from which to find the functions
  string writefile(const string& mrname, const vector<uint8_t>& so) {
    //specify location
    string filelocation = SO_PREFIX + mrname + ".so";
    files.push_back(filelocation);
    FILE *openwrite = fopen(filelocation.c_str(), "wb");
    
    if (!openwrite)
    {
      return "Error open file for writing";
    }
    size_t written = fwrite(so.data(), 1, so.size(), openwrite);
    fclose(openwrite);
    //if successfully wirte, then return location
    return written == so.size() ? filelocation : "Error write file";
  }

  // Load the .so file and extract map and reduce functions
  //
  /// @param filelocation The file's  location
  pair<void*, pair<map_func, reduce_func>> load_functions(const string& filelocation) {
    //load map and reduce from dynmic library
    void *dylibhandler = dlopen(filelocation.c_str(), RTLD_LAZY);
    if (!dylibhandler) return {nullptr, {nullptr, nullptr}};
    //dynamic loaded shared object
    auto map_so = (map_func)dlsym(dylibhandler, MAP_FUNC_NAME.c_str());
    auto reduce_so = (reduce_func)dlsym(dylibhandler, REDUCE_FUNC_NAME.c_str());
    if (!map_so || !reduce_so) {
      //fail to load
        dlclose(dylibhandler);
        return {nullptr, {nullptr, nullptr}};
    }
    return {dylibhandler, {map_so, reduce_so}};
  }

  /// Register the map() and reduce() functions from the provided .so, and
  /// associate them with the provided name.
  ///
  /// @param mrname The name to associate with the functions
  /// @param so     The so contents from which to find the functions
  ///
  /// @return a status message
  virtual std::string register_mr(const std::string &mrname,
                                  const std::vector<uint8_t> &so) {
    // TODO: Implement this
    //return RES_ERR_SO;
    // precheck error
    if (mrname.length() > LEN_FNAME)
    {
      return RES_ERR_FUNC;
    }
    //operations
    lock_guard<shared_mutex> lock(mutexx);
    if (funcmap.find(mrname) != funcmap.end())
    {
      return RES_ERR_FUNC;
    }
    //helper function to write
    string fileResult = writefile(mrname, so);
    //check if error occured
    if (fileResult.find("Error") == 0)
    {
       return RES_ERR_SO;
    }
    // load helper
    auto [dylibhandler, functions] = load_functions(fileResult);
    if (!dylibhandler) return RES_ERR_SO;
    //
    funcmap[mrname] = functions;
    handlers.push_back(dylibhandler);
    return RES_OK;
  }

  /// Get the (already-registered) map() and reduce() functions associated with
  /// a name.
  ///
  /// @param name The name with which the functions were mapped
  ///
  /// @return A pair of function pointers, or {nullptr, nullptr} on error
  virtual std::pair<map_func, reduce_func> get_mr(const std::string &mrname) {
    // TODO: Implement this
    //return {nullptr, nullptr};

    //find according to mrname
    shared_lock<shared_mutex> lock(mutexx);
    auto it = funcmap.find(mrname);
    //if not found
    return it != funcmap.end() ? it->second : make_pair(nullptr, nullptr);
  }

  /// When the function table shuts down, we need to de-register all the .so
  /// files that were loaded.
  virtual void shutdown() {
    // TODO: Implement this

    //clear all handler/map/file
    lock_guard<shared_mutex> lock(mutexx);
    for (auto handler : handlers) dlclose(handler);
    for (const auto& filename : files) remove(filename.c_str());
    funcmap.clear();
  
  }
};

/// Create a FuncTable
FuncTable *functable_factory() { return new my_functable(); };
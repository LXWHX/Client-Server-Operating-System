#include <iostream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include <linux/seccomp.h>
#include <sys/prctl.h>

#include "../common/constants.h"
#include "../common/contextmanager.h"

#include "functable.h"
#include "map.h"
#include "storage.h"

#include <cstring>

using namespace std;

/// Register a .so with the function table
///
/// @param user       The name of the user who made the request
/// @param pass       The password for the user, used to authenticate
/// @param mrname     The name to use for the registration
/// @param so         The .so file contents to register
/// @param admin_name The name of the admin user
/// @param funcs      A pointer to the function table
///
/// @return A result tuple, as described in storage.h
result_t my_register_mr(const string &user, const string &mrname,
                        const vector<uint8_t> &so,
                        const std::string &admin_name, FuncTable *funcs) {
  // Note: You can assume the user provided a valid password

  // TODO: Implement this
  //return {false, RES_ERR_UNIMPLEMENTED, {}};
  if(user != admin_name)
    {
      return {false,RES_ERR_LOGIN,{}};
    }
    else {
      string checkresok = funcs->register_mr(mrname,so);
      if (checkresok == RES_OK)
      {
         return {true,RES_OK,{}};
      }
      return {false,checkresok,{}};
    }
};


//helper serialize kv to uint8_t
//
/// @param dataout   store the serialized data
/// @param key        key string to serialize
/// @param value      value of vector uint8_t
void serialize(vector<uint8_t>& dataout, const string& key, const vector<uint8_t>& value) 
{
    uint32_t keylen = key.size();
    uint32_t vallen = value.size();
    dataout.reserve(4 + keylen + 4 + vallen);
    //reinterpret_cast instructs the compiler to treat expression as if it had  target-type
    dataout.insert(dataout.end(), reinterpret_cast<uint8_t*>(&keylen), reinterpret_cast<uint8_t*>(&keylen) + 4);
    dataout.insert(dataout.end(), key.begin(), key.end());
    dataout.insert(dataout.end(), reinterpret_cast<uint8_t*>(&vallen), reinterpret_cast<uint8_t*>(&vallen) + 4);
    dataout.insert(dataout.end(), value.begin(), value.end());
}

//deserialize kv
//
/// @param data       serialized data
/// @param key        store deserialized key
/// @param value      store the deserialized value
void deserialize(const vector<uint8_t>& data, string& key, vector<uint8_t>& value) 
{
    uint32_t keylen = *reinterpret_cast<const uint32_t*>(data.data());
    uint32_t vallen = *reinterpret_cast<const uint32_t*>(data.data() + 4 + keylen);
    key.assign(data.begin() + 4, data.begin() + 4 + keylen);
    value.assign(data.begin() + 4 + keylen + 4, data.begin() + 4 + keylen + 4 + vallen);
}

/// Run a map/reduce on all the key/value tuples of the kv_store
///
/// @param user       The name of the user who made the request
/// @param mrname     The name of the map/reduce functions to use
/// @param admin_name The name of the admin user
/// @param funcs      A pointer to the function table
/// @param kv_store   A pointer to the Map holding the key/value store
///
/// @return A result tuple, as described in storage.h
result_t my_invoke_mr(const string &user, const string &mrname,
                      const std::string &admin_name, FuncTable *funcs,
                      Map<string, vector<uint8_t>> *kv_store) {
  // Note: You can assume the user provided a valid password

  // TODO: Implement this
  //return {false, RES_ERR_UNIMPLEMENTED, {}};

  //2 pipeline for readwrite
  int rp[2], wp[2];
  //pid for storeid
  pid_t pid;

  //if pipe failed
  if (pipe(rp) == -1 || pipe(wp) == -1) 
  {
    return {false, RES_ERR_SO, {}};
  }

  pid = fork();
  
  //fork error
  if (pid < 0)
  {
    return {false, RES_ERR_SO, {}};
  }

  //0 means child process
  if (pid == 0)
  {
    //child process
    //close readwritewriteread
    close(rp[1]);
    close(wp[0]);
    //security protocol
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

    //all functions from so
    auto mrfuncs = funcs->get_mr(mrname);
    auto mapfunc = mrfuncs.first;
    auto reducefunc = mrfuncs.second;
    //if no func then exit
    if (mapfunc == nullptr)
    {
        exit(EXIT_FAILURE);
    }

    //map processing
    vector<vector<uint8_t>> map_results;
    char buf[4];
    ssize_t readbytes;
    //read to get data
    while ((readbytes = read(rp[0], buf, 4)) > 0)
    {
      uint32_t len;
      memcpy(&len, buf, 4);
      vector<uint8_t> data(len);
      if (read(rp[0], data.data(), len) != len)
      {
         //read error
        exit(EXIT_FAILURE);
      }

      //deserialize data to key/value
      string key;
      vector<uint8_t> value;
      deserialize(data, key, value);

      //execute map function
      vector<uint8_t> result = mapfunc(key, value);
      map_results.push_back(result);
    }
     //reduce processing
    auto reduceres = reducefunc(map_results);
    uint32_t result_size = reduceres.size();
    if (write(wp[1], &result_size, 4) != 4 || write(wp[1], reduceres.data(), result_size) != result_size)
    {
      //write error
       exit(EXIT_FAILURE);
    }
    //close and exit
    close(rp[0]);
    close(wp[1]);
    exit(EXIT_SUCCESS);
    } 
    else
    {
      //parent process
      //close readreadwritewrite
      close(rp[0]);
      close(wp[1]);
      //serialize and write to pipe
      kv_store->do_all_readonly([&](const string &key, const vector<uint8_t> &val) {
        vector<uint8_t> data;
        serialize(data, key, val);
        int32_t size = data.size();
        if (write(rp[1], &size, 4) != 4 || write(rp[1], data.data(), size) != size) {}
        }, [](){});
        //close write pipe
        close(rp[1]);
        //reduce result
        uint32_t result_size;
        vector<uint8_t> reduceres;
        if (read(wp[0], &result_size, 4) != 4)
        {
            return {false, RES_ERR_SERVER, {}};
        }
        reduceres.resize(result_size);
        if (read(wp[0], reduceres.data(), result_size) != result_size)
        {
            return {false, RES_ERR_SERVER, {}};
        }

        close(wp[0]);
        //check errors
        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            return {false, RES_ERR_SERVER, {}};
        }

        return {true, RES_OK, reduceres};
    }
}

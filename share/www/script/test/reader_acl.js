// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License.  You may obtain a copy
// of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
// License for the specific language governing permissions and limitations under
// the License.

couchTests.reader_acl = function(debug) {
  // this tests read access control

  var usersDb = new CouchDB("test_suite_users", {"X-Couch-Full-Commit":"false"});
  var secretDb = new CouchDB("test_suite_db", {"X-Couch-Full-Commit":"false"});
  function testFun() {
    try {
      usersDb.deleteDb();
      usersDb.createDb();
      secretDb.deleteDb();
      secretDb.createDb();

      // create a user with top-secret-clearance
      var jchrisUserDoc = CouchDB.prepareUserDoc({
        name: "jchris@apache.org",
        roles : ["top-secret"]
      }, "funnybone");
      T(usersDb.save(jchrisUserDoc).ok);
      usersDb.ensureFullCommit();

      T(CouchDB.session().userCtx.name == null);

      // set secret db to be read controlled
      T(secretDb.save({_id:"baz",foo:"bar"}).ok);
      T(secretDb.open("baz").foo == "bar");

      T(secretDb.setSecObj({
        "members" : {
          roles : ["super-secret-club"],
          names : ["joe","barb"]
        }
      }).ok);
    } finally {
      CouchDB.logout();
    }
  }
  
  // split into 2 funs so we can test restart behavior
  function testFun2() {
    try {
      // can't read it as jchris b/c he's missing the needed role
      T(CouchDB.login("jchris@apache.org", "funnybone").ok);
      T(CouchDB.session().userCtx.name == "jchris@apache.org");

      try {
        secretDb.open("baz");
        T(false && "can't open a doc from a secret db") ;
      } catch(e) {
        T(true)
      }

      CouchDB.logout();
      
      // make anyone with the top-secret role an admin
      // db admins are automatically members
      T(secretDb.setSecObj({
        "admins" : {
          roles : ["top-secret"],
          names : []
        },
        "members" : {
          roles : ["super-secret-club"],
          names : ["joe","barb"]
        }
      }).ok);


      T(CouchDB.login("jchris@apache.org", "funnybone").ok);

      // db admin can read
      T(secretDb.open("baz").foo == "bar");

      // and run temp views
      TEquals(secretDb.query(function(doc) {
        emit(null, null)
      }).total_rows, 1);

      CouchDB.logout();
      T(CouchDB.session().userCtx.roles.indexOf("_admin") != -1);

      // admin now adds the top-secret role to the db's members
      // and removes db-admins
      T(secretDb.setSecObj({
        "admins" : {
          roles : [],
          names : []
        },
        "members" : {
          roles : ["super-secret-club", "top-secret"],
          names : ["joe","barb"]
        }
      }).ok);

      // server _admin can always read
      T(secretDb.open("baz").foo == "bar");

      // and run temp views
      TEquals(secretDb.query(function(doc) {
        emit(null, null)
      }).total_rows, 1);

      T(secretDb.save({
        "_id" : "_design/foo",
        views : {
          bar : {
            map : "function(doc){emit(null, null)}"
          }
        }
      }).ok)

      // now top-secret users can read too
      T(CouchDB.login("jchris@apache.org", "funnybone").ok);
      T(CouchDB.session().userCtx.roles.indexOf("_admin") == -1);
      T(secretDb.open("baz").foo == "bar");
      // members can query stored views
      T(secretDb.view("foo/bar").total_rows == 1);
      
      // members can't do temp views
      try {
        var results = secretDb.query(function(doc) {
          emit(null, null);
        });
        T(false && "temp view should be admin only");
      } catch (e) {
        T(true && "temp view is admin only");
      }
      
      CouchDB.logout();

      // works with readers (backwards compat with 1.0)
      T(secretDb.setSecObj({
        "admins" : {
          roles : [],
          names : []
        },
        "readers" : {
          roles : ["super-secret-club", "top-secret"],
          names : ["joe","barb"]
        }
      }).ok);

      T(CouchDB.login("jchris@apache.org", "funnybone").ok);
      T(CouchDB.session().userCtx.roles.indexOf("_admin") == -1);
      T(secretDb.open("baz").foo == "bar");

      // can't set non string reader names or roles
      try {
        secretDb.setSecObj({
          "members" : {
            roles : ["super-secret-club", {"top-secret":"awesome"}],
            names : ["joe","barb"]
          }
        })
        T(false && "only string roles");
      } catch (e) {}

      try {
        secretDb.setSecObj({
          "members" : {
            roles : ["super-secret-club", {"top-secret":"awesome"}],
            names : ["joe",22]
          }
        });
        T(false && "only string names");
      } catch (e) {}
      
      try {
        secretDb.setSecObj({
          "members" : {
            roles : ["super-secret-club", {"top-secret":"awesome"}],
            names : "joe"
          }
        });
        T(false && "only lists of names");
      } catch (e) {}
    } finally {
      CouchDB.logout();
    }
  };

  function test_inbox_db() {
    try {
      function login(name) {
        var passwords = {"a_member":"honeyscone", "not_a_member":"bunnythrown"};
        var password = passwords[name];

        CouchDB.logout();
        if(name) {
          TEquals(true, CouchDB.login(name, password).ok, "Login: " + name);
        }

        TEquals(name, CouchDB.session().userCtx.name, "Good login: " + name);
      }

      // Start fresh.
      usersDb.deleteDb();
      usersDb.createDb();
      secretDb.deleteDb();
      secretDb.createDb();

      var validator = function(newDoc, oldDoc, userCtx, secObj) {
        if(!newDoc._deleted && !newDoc.is_ok)
          throw {forbidden: 'Set is_ok'};
      };

      var updater = function(doc, req) {
        doc = doc || {};
        doc.is_ok = true;
        doc.value = (doc.value || 0) + parseInt(req.query.n || "1");
        return [doc, "value is "+doc.value];
      };

      var hello = function(doc, req) {
        return { code:200,
                 headers: {"content-type":"text/plain"},
                 body:"Hello\r\n"
               };
      };

      var raygan = function(head, req) {
        start({headers:{"content-type":"text/plain"}});
        send("Hello\r\n");
      };

      validator = validator.toSource ? validator.toSource() : "(" + validator.toString() + ")";
      updater   = updater  .toSource ? updater  .toSource() : "(" + updater  .toString() + ")";
      hello     = hello    .toSource ? hello    .toSource() : "(" + hello    .toString() + ")";
      raygan    = raygan   .toSource ? raygan   .toSource() : "(" + raygan   .toString() + ")";
      var ddoc = { "_id": "_design/inbox",
                   "validate_doc_update": validator,
                   "views": {"ids":{"map":"function(doc) { emit(doc._id, 1) }"}},
                   "updates": {"inc":updater},
                   "shows"  : {"hello":hello},
                   "lists"  : {"raygan":raygan},
                   "rewrites": [
                     {"from":"r_from", "to":"../../r_to" },
                     {"from":"one/two/three/DATABASE", "to":"../../" }
                   ]
                 };

      TEquals(true, secretDb.save(ddoc).ok, "Save inbox db testing ddoc");

      CouchDB.logout();
      T(CouchDB.session().userCtx.roles.indexOf('_admin') !== -1, "Become server admin");

      var doc;

      doc = CouchDB.prepareUserDoc({name: "a_member", roles:[]}, "honeyscone");
      TEquals(true, usersDb.save(doc).ok, "Create member user");

      doc = CouchDB.prepareUserDoc({name: "not_a_member", roles:[]}, "bunnythrown");
      TEquals(true, usersDb.save(doc).ok, "Create non-member user");

      usersDb.ensureFullCommit();

      // Judiciously duplicate some of the _security and validator tests. This
      // affirms that legacy functionality stays unchanged, before running the
      // subsequent tests which directly confirm the feature. It should be
      // obvious and easy to reason about, because an inbox mode allows
      // non-members and anonymous users to update a private database!

      var _security, xhr, result, expected;
      _security = { "admins" : { roles:[], names:["jchris@apache.org"] },
                    "members": { roles:[], names:["a_member"] }
                  };

      TEquals(true, secretDb.setSecObj(_security).ok, "Set security, no inbox");

      login("a_member");

      doc = {_id:"a_doc", is_ok:true};
      TEquals(true, secretDb.save(doc).ok, "DB member may update");

      login("not_a_member");

      try      { secretDb.open("a_doc");
                 T(false, "Non-member may not read a doc") }
      catch(e) { TEquals("unauthorized", e.error, "Non-member may not read a doc") }

      try      { secretDb.save({ _id:"nonmember_doc" });
                 T(false, "Non-member may not update"); }
      catch(e) { TEquals("unauthorized", e.error, "Non-member may not update") }

      try      { secretDb.save({ _id:"nonmember_doc2", is_ok:true });
                 T(false, "Non-member may not make a valid update"); }
      catch(e) { TEquals("unauthorized", e.error, "Non-member may not make a valid update") }

      xhr = CouchDB.request("POST", secretDb.uri, {
        headers: {"Content-Type": "application/json"},
        body   : JSON.stringify({_id:"nonmember_post", is_ok:true})
      });
      TEquals(401, xhr.status, "Non-member may not POST to the DB");

      // Confirm allowed actions.

      _security = { "admins" : { roles:[], names:["jchris@apache.org"] },
                    "members": { roles:[], names:["a_member"],
                                 allow_anonymous_writes:true
                               }
                  };

      login(null);
      TEquals(true, secretDb.setSecObj(_security).ok, "Set security with inbox");

      login("not_a_member");

      try      { secretDb.save({ _id:"nonmember_invalid", is_ok:false });
                 T(false, "Must validate non-member doc") }
      catch(e) { TEquals("forbidden", e.error , "Must validate non-member doc");
                 TEquals("Set is_ok", e.reason, "Must validate non-member doc") }

      doc = { _id:"nonmember_valid", value:7, is_ok:true };
      xhr = CouchDB.request("POST", secretDb.uri, {
        headers: {"Content-Type": "application/json"},
        body   : JSON.stringify(doc)
      });
      result = JSON.parse(xhr.responseText);
      TEquals(201, xhr.status, "Non-member may POST to the DB");
      TEquals("nonmember_valid", result.id, "Non-member may POST to the DB");

      doc._rev = result.rev;
      doc.value = 11;
      result = secretDb.save(doc);
      TEquals(true, result.ok, "Non-member may create a valid doc");

      doc.updating = "second iteration";
      result = secretDb.save(doc);
      TEquals(true, result.ok, "Non-member may update a valid doc");

      doc._attachments = {
        "inline.txt": {
          content_type:"text/plain",
          data: "VGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHRleHQ="
        }
      };
      result = secretDb.save(doc);
      TEquals(true, result.ok, "Non-member may attach to a valid doc");

      var attachment = secretDb.uri + doc._id + "/standalone.txt";
      xhr = CouchDB.request("PUT", attachment+"?rev="+doc._rev, {
        headers: {"Content-Type": "text/plain;charset=utf-8"},
        body   : "This inbox attachment is no base64-encoded text"
      });
      TEquals(201, xhr.status, "Non-member may make standalone attachments");

      doc._rev = xhr.getResponseHeader("Etag");
      doc._rev = doc._rev.substr(1, doc._rev.length - 2); // Strip quotes
      xhr = CouchDB.request("DELETE", attachment+"?rev="+doc._rev);
      TEquals(200, xhr.status, "Non-member may directly delete attachments");

      doc._rev = xhr.getResponseHeader("X-Couch-Update-NewRev");
      expected = "value is " + (doc.value + 23);
      xhr = CouchDB.request("PUT", secretDb.uri + ddoc._id + "/_update/inc/" + doc._id + "?n=23");
      TEquals(201, xhr.status, "Non-member may update via _update");
      TEquals(expected, xhr.responseText, "Non-member receives update function output");

      doc.value += 23;
      doc._rev = xhr.getResponseHeader("X-Couch-Update-NewRev");
      TEquals('string', typeof doc._rev, "Non-member receives new rev from update function");

      result = secretDb.deleteDoc(doc);
      TEquals(true, result.ok, "Non-member may delete a doc");

      expected = "value is 87";
      xhr = CouchDB.request("POST", secretDb.uri + ddoc._id + "/_update/inc?n=87");
      TEquals(201, xhr.status, "Non-member may create via _update");
      TEquals(expected, xhr.responseText, "Non-member receives update function output");

      doc = {id_should_be:"r_to", is_ok:true};
      xhr = CouchDB.request("PUT", secretDb.uri+ddoc._id +"/_rewrite/r_from", {
        headers: {"Content-Type": "application/json"},
        body   : JSON.stringify(doc)
      });
      result = JSON.parse(xhr.responseText);
      TEquals(201, xhr.status, "Non-member may use rewrites");
      TEquals("r_to", result.id, "Non-member may use rewrites");

      doc = {_id:"in_db", is_ok:true};
      xhr = CouchDB.request("POST",
          secretDb.uri + ddoc._id + "/_rewrite/one/two/three/DATABASE", {
        headers: {"Content-Type": "application/json"},
        body   : JSON.stringify(doc)
      });
      result = JSON.parse(xhr.responseText);
      TEquals(201, xhr.status, "Non-member may use rewrites");
      TEquals("in_db", result.id, "Non-member may use rewrites");

      // Confirm disallowed actions.

      try      { secretDb.open("a_doc");
                 T(false, "Non-member may not read an inbox doc") }
      catch(e) { TEquals("unauthorized", e.error, "Non-member may not read an inbox doc") }

      try      { secretDb.query(function(doc) { emit(1,0) });
                 T(false, "Non-member may not run a temporary view") }
      catch(e) { TEquals("unauthorized", e.error, "Non-member may not read") }

      try      { result = secretDb.view("inbox/ids", {}, ["a_doc", "song"]);
                 T(false, "Non-member may not POST to a view") }
      catch(e) { TEquals("unauthorized", e.error, "Non-member may not POST to a view") }

      try      { result = secretDb.view("inbox/ids", {}, ["a_doc", "song"]);
                 T(false, "Non-member may not POST to a view") }
      catch(e) { TEquals("unauthorized", e.error, "Non-member may not POST to a view") }

      xhr = CouchDB.request("POST", secretDb.uri + "a_doc", {
        headers: {"X-HTTP-Method-Override":"GET"}
      });
      TEquals(401, xhr.status, "Non-member may not POST Method-Override to inbox DB");

      xhr = CouchDB.request("POST", secretDb.uri + "_all_docs", {
        headers: {"Content-Type": "application/json"},
        body   : JSON.stringify({keys: ["a_doc"]})
      });
      TEquals(401, xhr.status, "Non-member may not POST to inbox DB _all_docs");

      xhr = CouchDB.request("POST", secretDb.uri + "_changes", {
        headers: {"Content-Type": "application/json"}
      });
      TEquals(401, xhr.status, "Non-member may not POST to inbox DB _changes");

      xhr = CouchDB.request("POST", secretDb.uri + "_changes", {
        headers: {"Content-Type": "application/json"}
      });
      TEquals(401, xhr.status, "Non-member may not POST to inbox DB _changes");

      xhr = CouchDB.request("GET", secretDb.uri+ddoc._id +"/_rewrite/r_from");
      TEquals(401, xhr.status, "Non-member may not read rewrites");

      xhr = CouchDB.request("HEAD",
        secretDb.uri + ddoc._id + "/_rewrite/one/two/three/DATABASE/in_db");
      TEquals(401, xhr.status, "Non-member may not read rewrites");

      var funcs = ["_show/hello/a_doc", "_list/raygan/ids"];
      var methods = ["GET", "PUT", "POST", "OPTIONS", "MEANINGLESS", "METHODS"];
      funcs.forEach(function(func) {
        methods.forEach(function(method) {
          var path = secretDb.uri + ddoc._id + "/" + func;
          xhr = CouchDB.request(method, path);
          TEquals(401, xhr.status, "Non-member may not _show or _list inbox");
        });
      });

      // Test semantic errors in _security.

      _security = { "admins" : { roles:[], names:["jchris@apache.org"] },
                    "members": { roles:[], names:["a_member"]          },
                    "allow_anonymous_writes": true
                  };
      login(null);
      TEquals(true,secretDb.setSecObj(_security).ok, "Set inbox DB security");

      login("not_a_member");
      try      { secretDb.save({_id:"not_really_inbox"});
                 T(false, "Non-member may not update erroneous inbox") }
      catch(e) { TEquals("unauthorized", e.error,
                         "Non-member may not update erroneous inbox")  }

      var not_true_enough = [1, "true", [true], {"true":true}];
      not_true_enough.forEach(function(inbox_val, i) {
        _security = { "admins" : { roles:[], names:["jchris@apache.org"] },
                      "members": { roles:[], names:["a_member"],
                                   allow_anonymous_writes: inbox_val
                                 }
                    };

        login(null);
        TEquals(true,secretDb.setSecObj(_security).ok, "Set inbox DB security");

        login("not_a_member");
        try      { secretDb.save({_id:"not_really_inbox" + i});
                   T(false, "Non-member may not update erroneous inbox") }
        catch(e) { TEquals("unauthorized", e.error,
                           "Non-member may not update erroneous inbox")  }
      });

    } finally {
      CouchDB.logout();
    }
  }

  // Execute the test functions, in order, with a restart between each of them.
  var test_functions = [testFun, testFun2, test_inbox_db];
  var config_modification = [
    {section: "httpd",
      key: "authentication_handlers",
      value: "{couch_httpd_auth, cookie_authentication_handler}, {couch_httpd_auth, default_authentication_handler}"},
    {section: "couch_httpd_auth",
      key: "authentication_db", value: "test_suite_users"}];

  test_functions.forEach(function(test_function, i) {
    run_on_modified_server(config_modification, test_function);
    if(i+1 < test_functions.length) {
      // Restart to prepare for more tests.
      restartServer();
    }
  });
}

/* Any copyright is dedicated to the Public Domain.
 * http://creativecommons.org/publicdomain/zero/1.0/ */
 
using System;
using System.Reflection;
using System.Threading.Tasks;

using Microsoft.VisualStudio.TestTools.UnitTesting;
using NLog;

using Butterfly.Auth;
using Butterfly.Db;
using Butterfly.Util;

namespace Butterfly.Core.Test {
    [TestClass]
    public class AuthTest {
        protected static readonly Logger logger = LogManager.GetCurrentClassLogger();

        [TestMethod]
        public async Task SimpleTest() {
            var database = new Butterfly.Db.Memory.MemoryDatabase();

            await database.CreateFromResourceFileAsync(Assembly.GetExecutingAssembly(), "Butterfly.Auth.Test.db.sql");
            database.SetDefaultValue("id", tableName => Guid.NewGuid().ToString());
            database.SetDefaultValue("created_at", tableName => DateTime.Now.ToUnixTimestamp());
            database.SetDefaultValue("updated_at", tableName => DateTime.Now.ToUnixTimestamp());
            database.AddInputPreprocessor(BaseDatabase.RemapTypeInputPreprocessor<DateTime>(dateTime => dateTime.ToUnixTimestamp()));

            // Create a single instance of AuthManager
            AuthManager authManager = new AuthManager(database, userTableRoleFieldName: null);

            // Register a user
            UserRefToken registerAuthToken = await authManager.RegisterAsync(new {
                username = "johnsmith",
                first_name = "John",
                last_name = "Smith",
                email = "john@fireshark.com",
                phone = "+13162105368",
                password = "test123"
            });
            //if (database.CanJoin) {
                AuthToken authToken = await authManager.AuthenticateAsync(UserRefTokenAuthenticator.AUTH_TYPE, registerAuthToken.id);
            //}

            await authManager.ForgotPasswordAsync("johnsmith");
        }

    }
}

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
        public async Task RegistrationTests() {
            var database = new Butterfly.Db.Memory.MemoryDatabase();

            await database.CreateFromResourceFileAsync(Assembly.GetExecutingAssembly(), "Butterfly.Auth.Test.butterfly_auth_test.sql");
            database.SetDefaultValue("id", tableName => Guid.NewGuid().ToString());
            database.SetDefaultValue("created_at", tableName => DateTime.Now.ToUnixTimestamp());
            database.SetDefaultValue("updated_at", tableName => DateTime.Now.ToUnixTimestamp());
            database.AddInputPreprocessor(BaseDatabase.RemapTypeInputPreprocessor<DateTime>(dateTime => dateTime.ToUnixTimestamp()));

            // Create a single instance of AuthManager
            AuthManager authManager = new AuthManager(database);

            // Register a valid user
            UserRefToken registerAuthToken1 = await authManager.RegisterAsync(new {
                username = "johnsmith",
                first_name = "John",
                last_name = "Smith",
                email = "john@fireshark.com",
                phone = "+13162105368",
                password = "test123"
            });

            // Verify the returned auth token can be authenticated
            var authToken1 = await authManager.AuthenticateAsync(UserRefTokenAuthenticator.AUTH_TYPE, registerAuthToken1.id);

            // Register an invalid email
            Exception exception2 = null;
            try {
                UserRefToken registerAuthToken2 = await authManager.RegisterAsync(new {
                    username = "johnsmith2",
                    first_name = "John",
                    last_name = "Smith",
                    email = "john",
                    phone = "+13162105368",
                    password = "test123"
                });
            }
            catch (Exception e) {
                exception2 = e;
            }
            Assert.IsTrue(exception2.Message.Contains("Email address must contain"));

            // Register an invalid phone
            Exception exception3 = null;
            try {
                UserRefToken registerAuthToken2 = await authManager.RegisterAsync(new {
                    username = "johnsmith2",
                    first_name = "John",
                    last_name = "Smith",
                    email = "john@fireshark.com",
                    phone = "123",
                    password = "test123"
                });
            }
            catch (Exception e) {
                exception3 = e;
            }
            Assert.IsTrue(exception3.Message.Contains("Invalid phone number"));

            // Register a duplicate username
            Exception exception4 = null;
            try {
                UserRefToken registerAuthToken2 = await authManager.RegisterAsync(new {
                    username = "johnsmith",
                    first_name = "John",
                    last_name = "Smith",
                    email = "john@fireshark.com",
                    phone = "+13162105368",
                    password = "test123"
                });
            }
            catch (Exception e) {
                exception4 = e;
            }
            Assert.IsTrue(exception4.Message.Contains("unavailable"));

            // Register without a password
            Exception exception5 = null;
            try {
                UserRefToken registerAuthToken2 = await authManager.RegisterAsync(new {
                    username = "johnsmith2",
                    first_name = "John",
                    last_name = "Smith",
                    email = "john@fireshark.com",
                    phone = "+13162105368"
                });
            }
            catch (Exception e) {
                exception5 = e;
            }
            Assert.IsTrue(exception5.Message.Contains("password cannot be null"));
        }

    }
}

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using NLog;

using Butterfly.Db;
using Butterfly.Util;
using Butterfly.Util.Field;
using Butterfly.Web.WebApi;

using Dict = System.Collections.Generic.Dictionary<string, object>;

namespace Butterfly.Auth {
    /// <summary>
    /// Provides an API to register users, login users, handle forgot password requests, reset password requests, and validate auth tokens. 
    /// </summary>
    /// <remarks>
    /// Can be initialized like this...
    /// <code>
    ///     var database = (initialize an IDatabase instance here)
    ///     var notifyManager = (initialize NotifyManager here)
    ///     var welcomeEmailNotifyMessage = (load welcome email here)
    ///     var resetEmailNotifyMessage = (load reset email here)
    ///     var authManager = new AuthManager(
    ///         database,
    ///         defaultRole: "full-access",
    ///         onEmailVerify: notifyManager.VerifyAsync,
    ///         onPhoneVerify: notifyManager.VerifyAsync,
    ///         onRegister: user => {
    ///             notifyManager.Queue(welcomeEmailNotifyMessage.Evaluate(user));
    ///         },
    ///         onForgotPassword: user => {
    ///             notifyManager.Queue(resetEmailNotifyMessage.Evaluate(user));
    ///         }
    ///     );
    /// </code>
    /// 
    /// The following database tables are recommended (using MySQL syntax but use any database supported by Butterfly.Db)...
    /// <code>
    /// CREATE TABLE account (
    /// 	id VARCHAR(50) NOT NULL,
    ///     created_at INT NOT NULL,
    /// 	updated_at INT NOT NULL,
    ///     PRIMARY KEY(id)
    /// );
    /// 
    /// CREATE TABLE user(
    ///     id VARCHAR(50) NOT NULL,
    ///     account_id VARCHAR(50) NOT NULL,
    ///     username VARCHAR(40) NOT NULL,
    ///     first_name VARCHAR(255) NOT NULL,
    ///     last_name VARCHAR(255) NOT NULL,
    ///     email VARCHAR(255) NOT NULL,
    ///     email_verified_at INT NULL,
    ///     phone VARCHAR(20) NULL,
    /// 	phone_verified_at INT NULL,
    /// 	role VARCHAR(25) NULL,
    /// 	salt VARCHAR(40) NOT NULL,
    ///     password_hash VARCHAR(90) NOT NULL,
    ///     reset_code VARCHAR(6) NULL,	
    /// 	reset_code_expires_at INT NULL,	
    /// 	created_at INT NOT NULL,
    ///     updated_at INT NOT NULL,
    /// 	PRIMARY KEY(id),
    /// 	UNIQUE INDEX username(username)
    /// );
    /// 
    /// CREATE TABLE auth_token(
    ///     id VARCHAR(50) NOT NULL,
    ///     user_id VARCHAR(50) NOT NULL,
    ///     expires_at INT NOT NULL,
    /// 	created_at INT NOT NULL,
    ///     PRIMARY KEY(id)
    /// );
    /// </code>
    /// </remarks>
    public class AuthManager {
        protected static readonly Logger logger = LogManager.GetCurrentClassLogger();

        protected readonly IDatabase database;

        protected readonly int authTokenDurationDays;
        protected readonly int resetCodeLength;
        protected readonly int resetTokenDurationMinutes;

        protected readonly string accountTableName;
        protected readonly string accountTableIdFieldName;
        protected readonly string accountTableShareCodeFieldName;

        protected readonly string userTableName;
        protected readonly string userTableIdFieldName;
        protected readonly string userTableUsernameFieldName;
        protected readonly string userTableEmailFieldName;
        protected readonly string userTableEmailVerifiedAtFieldName;
        protected readonly string userTablePhoneFieldName;
        protected readonly string userTablePhoneVerifiedAtFieldName;
        protected readonly string userTableSaltFieldName;
        protected readonly string userTablePasswordHashFieldName;
        protected readonly string userTableFirstNameFieldName;
        protected readonly string userTableLastNameFieldName;
        protected readonly string userTableResetCodeFieldName;
        protected readonly string userTableResetCodeExpiresAtFieldName;
        protected readonly string userTableAccountIdFieldName;
        protected readonly string userTableRoleFieldName;

        protected readonly string defaultRole;

        protected readonly Func<Dict, Dict> getExtraAccountInfo;
        protected readonly Func<Dict, Dict> getExtraUserInfo;
        protected readonly Func<string, string, Task> onSendEmailVerifyCode;
        protected readonly Func<string, string, Task> onSendPhoneVerifyCode;
        protected readonly Func<Dict, Task> onVerified;

        protected readonly Func<bool, Dict, Task> onRegister;
        protected readonly Func<Dict, Task> onForgotPassword;
        protected readonly Func<Dict, Task> onForgotUsername;
        protected readonly Action<Version> onCheckVersion;

        public readonly IFieldValidator usernameFieldValidator;
        public readonly IFieldValidator passwordFieldValidator;
        public readonly IFieldValidator nameFieldValidator;
        public readonly IFieldValidator emailFieldValidator;
        public readonly IFieldValidator phoneFieldValidator;

        protected readonly Dictionary<string, IAuthenticator> authenticatorByType;

        protected readonly UserRefTokenAuthenticator userRefTokenAuthenticator;
        protected readonly ShareCodeAuthenticator shareCodeAuthenticator;

        protected readonly string sendVerifyTableName;
        protected readonly int verifyCodeExpiresSeconds;
        protected readonly string verifyCodeFormat;

        protected readonly static EmailFieldValidator EMAIL_FIELD_VALIDATOR = new EmailFieldValidator("email", false, true);
        protected readonly static PhoneFieldValidator PHONE_FIELD_VALIDATOR = new PhoneFieldValidator("phone", false);

        protected readonly static Random RANDOM = new Random();


        /// <summary>
        /// Create an instance of AuthManager
        /// </summary>
        /// <param name="database"></param>
        /// <param name="authTokenDurationDays">How long new <see cref="AuthToken"/> instances are valid for</param>
        /// <param name="resetCodeLength">How many digits should a reset code be</param>
        /// <param name="resetTokenDurationMinutes">How long new reset codes are valid for</param>
        /// <param name="accountTableName">Table name of the account table (default is "account")</param>
        /// <param name="accountTableIdFieldName">Field name of the id field on the account table (default is "id")</param>
        /// <param name="accountTableShareCodeFieldName">Field name of the share code field on the account table (default is "share_code")</param>
        /// <param name="userTableName">Table name of the user table (default is "user")</param>
        /// <param name="userTableIdFieldName">Field name of the id field on the user table (default is "id")</param>
        /// <param name="userTableUsernameFieldName">Field name of the username field on the user table (default is "username")</param>
        /// <param name="userTableEmailFieldName">Field name of the email field on the user table (default is "email")</param>
        /// <param name="userTableEmailVerifiedAtFieldName">Field name of the email verified at field on the user table (default is "email_verified_at")</param>
        /// <param name="userTablePhoneFieldName">Field name of the phone field on the user table (default is "phone")</param>
        /// <param name="userTablePhoneVerifiedAtFieldName">Field name of the phone verified at field on the user table (default is "phone_verified_at")</param>
        /// <param name="userTableSaltFieldName">Field name of the salt field on the user table (default is "salt")</param>
        /// <param name="userTablePasswordHashFieldName">Field name of the password hash field on the user table (default is "password_hash")</param>
        /// <param name="userTableFirstNameFieldName">Field name of the first name field on the user table (default is "first_name")</param>
        /// <param name="userTableLastNameFieldName">Field name of the last name field on the user table (default is "last_name")</param>
        /// <param name="userTableResetCodeFieldName">Field name of the reset code field on the user table (default is "reset_code")</param>
        /// <param name="userTableResetCodeExpiresAtFieldName">Field name of the reset code expires at field on the user table (default is "reset_code_expires_at")</param>
        /// <param name="userTableAccountIdFieldName">Field name of the account id field on the user table (default is "account_id")</param>
        /// <param name="userTableRoleFieldName">Field name of the role field on the user table (default is "role")</param>
        /// <param name="defaultRole">Default value for the role field on a new user</param>
        /// <param name="sendVerifyTableName"></param>
        /// <param name="verifyCodeExpiresSeconds"></param>
        /// <param name="verifyCodeFormat"></param>
        /// <param name="getExtraAccountInfo"></param>
        /// <param name="getExtraUserInfo"></param>
        /// <param name="onSendEmailVerifyCode"></param>
        /// <param name="onSendPhoneVerifyCode"></param>
        /// <param name="onVerified"></param>
        /// <param name="onRegisterAccount">Callback when a new account is registered</param>
        /// <param name="onRegister">Callback when a new user is registered</param>
        /// <param name="onForgotPassword">Callback when a forgot password request is made</param>
        /// <param name="onForgotUsername">Callback when a forgot username request is made</param>
        /// <param name="onCheckVersion"></param>
        public AuthManager(
            IDatabase database,
            int authTokenDurationDays = 90,
            int resetCodeLength = 6,
            int resetTokenDurationMinutes = 90,
            string accountTableName = "account",
            string accountTableIdFieldName = "id",
            string accountTableShareCodeFieldName = "share_code",
            string userTableName = "user",
            string userTableIdFieldName = "id",
            string userTableUsernameFieldName = "username",
            string userTableEmailFieldName = "email",
            string userTableEmailVerifiedAtFieldName = "email_verified_at",
            string userTablePhoneFieldName = "phone",
            string userTablePhoneVerifiedAtFieldName = "phone_verified_at",
            string userTableSaltFieldName = "salt",
            string userTablePasswordHashFieldName = "password_hash",
            string userTableFirstNameFieldName = "first_name",
            string userTableLastNameFieldName = "last_name",
            string userTableResetCodeFieldName = "reset_code",
            string userTableResetCodeExpiresAtFieldName = "reset_code_expires_at",
            string userTableAccountIdFieldName = "account_id",
            string userTableRoleFieldName = "role",
            string defaultRole = null,

            string sendVerifyTableName = "send_verify", 
            int verifyCodeExpiresSeconds = 3600,             
            string verifyCodeFormat = "###-###",

            Func<Dict, Dict> getExtraAccountInfo = null,
            Func<Dict, Dict> getExtraUserInfo = null,
            Func<string, string, Task> onSendEmailVerifyCode = null,
            Func<string, string, Task> onSendPhoneVerifyCode = null,
            Func<Dict, Task> onVerified = null,
            Func<bool, Dict, Task> onRegister = null,
            Func<Dict, Task> onForgotPassword = null,
            Func<Dict, Task> onForgotUsername = null,
            Action<Version> onCheckVersion = null
        ) {
            this.database = database;

            this.authTokenDurationDays = authTokenDurationDays;
            this.resetCodeLength = resetCodeLength;
            this.resetTokenDurationMinutes = resetTokenDurationMinutes;

            this.accountTableName = accountTableName;
            this.accountTableIdFieldName = accountTableIdFieldName;
            this.accountTableShareCodeFieldName = accountTableShareCodeFieldName;

            this.userTableName = userTableName;
            this.userTableIdFieldName = userTableIdFieldName;
            this.userTableUsernameFieldName = userTableUsernameFieldName;
            this.userTableEmailFieldName = userTableEmailFieldName;
            this.userTableEmailVerifiedAtFieldName = userTableEmailVerifiedAtFieldName;
            this.userTablePhoneFieldName = userTablePhoneFieldName;
            this.userTablePhoneVerifiedAtFieldName = userTablePhoneVerifiedAtFieldName;
            this.userTableSaltFieldName = userTableSaltFieldName;
            this.userTablePasswordHashFieldName = userTablePasswordHashFieldName;
            this.userTableFirstNameFieldName = userTableFirstNameFieldName;
            this.userTableLastNameFieldName = userTableLastNameFieldName;
            this.userTableResetCodeFieldName = userTableResetCodeFieldName;
            this.userTableResetCodeExpiresAtFieldName = userTableResetCodeExpiresAtFieldName;
            this.userTableAccountIdFieldName = userTableAccountIdFieldName;
            this.userTableRoleFieldName = userTableRoleFieldName;

            this.defaultRole = defaultRole;

            this.getExtraAccountInfo = getExtraAccountInfo;
            this.getExtraUserInfo = getExtraUserInfo;

            this.onRegister = onRegister;
            this.onSendEmailVerifyCode = onSendEmailVerifyCode;
            this.onSendPhoneVerifyCode = onSendPhoneVerifyCode;
            this.onVerified = onVerified;
            this.onForgotPassword = onForgotPassword;
            this.onForgotUsername = onForgotUsername;
            this.onCheckVersion = onCheckVersion;

            this.usernameFieldValidator = new GenericFieldValidator(this.userTableUsernameFieldName, @"^[_A-z0-9\-\.\@\+]{3,25}$", allowNull: false, forceLowerCase: true, includeValueInError: true);
            this.passwordFieldValidator = new GenericFieldValidator("password", "^.{6,255}$", allowNull: false, forceLowerCase: false, includeValueInError: false);
            this.nameFieldValidator = new TextFieldValidator(this.userTableLastNameFieldName, allowNull: false, maxLength: 25);
            this.emailFieldValidator = new EmailFieldValidator(this.userTableEmailFieldName, allowNull: true);
            this.phoneFieldValidator = new PhoneFieldValidator(this.userTablePhoneFieldName, allowNull: false);

            this.sendVerifyTableName = sendVerifyTableName;
            this.verifyCodeExpiresSeconds = verifyCodeExpiresSeconds;
            this.verifyCodeFormat = verifyCodeFormat;

            this.userRefTokenAuthenticator = new UserRefTokenAuthenticator(
                database,
                userTableName: this.userTableName,
                userTableUsernameFieldName: this.userTableUsernameFieldName,
                userTableAccountIdFieldName: this.userTableAccountIdFieldName,
                userTableRoleFieldName: this.userTableRoleFieldName
            );

            this.shareCodeAuthenticator = new ShareCodeAuthenticator(
                database,
                accountTableName: this.accountTableName,
                accountTableIdFieldName: this.accountTableIdFieldName,
                accountTableShareCodeFieldName: this.accountTableShareCodeFieldName
            );

            this.authenticatorByType = new Dictionary<string, IAuthenticator> {
                [UserRefTokenAuthenticator.AUTH_TYPE] = this.userRefTokenAuthenticator,
                [ShareCodeAuthenticator.AUTH_TYPE] = this.shareCodeAuthenticator
            };
        }

        protected readonly static Regex VERSION_CLEAN_REGEX = new Regex(@"[^\d\.]+");

        /// <summary>
        /// Call to setup a Web API with the specified <paramref name="webApi"/>
        /// </summary>
        /// <remarks>
        /// The following API URLs will be setup...
        /// <code>
        ///     GET /api/auth/check-username/{username}
        ///     GET /api/auth/check-auth-token/{id}
        ///     POST /api/auth/create-anonymous
        ///     POST /api/auth/register
        ///     POST /api/auth/login
        ///     POST /api/auth/forgot-password
        ///     POST /api/auth/reset-password
        ///     POST /api/auth/verify
        /// </code>
        /// </remarks>
        /// <param name="webApi"></param>
        /// <param name="pathPrefix">Defaults to /api/auth</param>
        public void SetupWebApi(IWebApi webApi, string pathPrefix = "/api/auth") {
            webApi.OnGet($"{pathPrefix}/check-username/{{username}}", async(req, res) => {
                string username = req.PathParams.GetAs("username", (string)null);
                logger.Debug($"/check-username/{username}");
                Dict user = await this.LookupUsernameAsync(username, this.userTableIdFieldName);
                bool available = user == null;
                await res.WriteAsJsonAsync(available);
            });

            webApi.OnGet($"{pathPrefix}/check-user-ref-token/{{id}}", async (req, res) => {
                string id = req.PathParams.GetAs("id", (string)null);
                string rawVersionText = req.QueryParams.GetAs("v", "");
                string versionText = VERSION_CLEAN_REGEX.Replace(rawVersionText, "");
                Version version = string.IsNullOrEmpty(versionText) ? null : Version.Parse(versionText);
                logger.Debug($"/check-auth-token/{id}?v={version}"); //?join_code={joinCode}");
                if (this.onCheckVersion != null) this.onCheckVersion(version);
                AuthToken authToken = await this.AuthenticateAsync(UserRefTokenAuthenticator.AUTH_TYPE, id);
                await res.WriteAsJsonAsync(authToken);
            });

            webApi.OnPost($"{pathPrefix}/create-anonymous", async(req, res) => {
                Dict data = await req.ParseAsJsonAsync<Dict>();
                AuthToken authToken = await this.CreateAnonymousUserAsync();
                await res.WriteAsJsonAsync(authToken);
            });

            webApi.OnPost($"{pathPrefix}/register", async(req, res) => {
                Dict registration = await req.ParseAsJsonAsync<Dict>();
                AuthToken authToken = await this.RegisterAsync(registration);
                await res.WriteAsJsonAsync(authToken);
            });

            webApi.OnPost($"{pathPrefix}/login", async(req, res) => {
                Dict login = await req.ParseAsJsonAsync<Dict>();
                AuthToken authToken = await this.LoginAsync(login);
                await res.WriteAsJsonAsync(authToken);
            });

            webApi.OnPost($"{pathPrefix}/forgot-password", async(req, res) => {
                Dict data = await req.ParseAsJsonAsync<Dict>();
                string username = data.GetAs("username", (string)null);
                await this.ForgotPasswordAsync(username);
            });

            webApi.OnPost($"{pathPrefix}/reset-password", async(req, res) => {
                Dict resetPassword = await req.ParseAsJsonAsync<Dict>();
                AuthToken authToken = await this.ResetPasswordAsync(resetPassword);
                await res.WriteAsJsonAsync(authToken);
            });

            webApi.OnPost($"{pathPrefix}/forgot-username", async (req, res) => {
                Dict data = await req.ParseAsJsonAsync<Dict>();
                string contact = data.GetAs("contact", (string)null);
                await this.ForgotUsernameAsync(contact);
            });

            webApi.OnPost($"{pathPrefix}/send-email-verify-code", async (req, res) => {
                UserRefToken userRefToken = await this.GetUserRefToken(req);

                string email = await this.database.SelectValueAsync<string>("SELECT email FROM user", vars: userRefToken.userId);
                await this.SendVerifyCodeAsync(email);
            });

            webApi.OnPost($"{pathPrefix}/send-phone-verify-code", async (req, res) => {
                UserRefToken userRefToken = await this.GetUserRefToken(req);

                string phone = await this.database.SelectValueAsync<string>("SELECT phone FROM user", vars: userRefToken.userId);
                await this.SendVerifyCodeAsync(phone);
            });


            webApi.OnPost($"{pathPrefix}/verify", async (req, res) => {
                Dict data = await req.ParseAsJsonAsync<Dict>();
                await this.VerifyAsync(data);
            });
        }

        public async Task SendVerifyCodeAsync(string contact) {
            logger.Debug($"SendVerifyCodeAsync():contact={contact}");

            // Scrub contact
            string scrubbedContact = Validate(contact);
            logger.Debug($"SendVerifyCodeAsync():scrubbedContact={scrubbedContact}");

            // Generate code and expires at
            int digits = this.verifyCodeFormat.Count(x => x == '#');
            int min = (int)Math.Pow(10, digits - 1);
            int max = (int)Math.Pow(10, digits) - 1;
            int code = RANDOM.Next(0, max - min) + min;
            logger.Debug($"SendVerifyCodeAsync():digits={digits},min={min},max={max},code={code}");
            DateTime expiresAt = DateTime.Now.AddSeconds(this.verifyCodeExpiresSeconds);

            // Insert/update database
            string id = await this.database.SelectValueAsync<string>($"SELECT id FROM {this.sendVerifyTableName}", new {
                contact = scrubbedContact
            });

            using (ITransaction transaction = await this.database.BeginTransactionAsync()) {
                if (id == null) {
                    await transaction.InsertAsync<string>(this.sendVerifyTableName, new {
                        contact = scrubbedContact,
                        verify_code = code,
                        expires_at = expiresAt,
                    });
                }
                else {
                    await transaction.UpdateAsync(this.sendVerifyTableName, new {
                        id,
                        verify_code = code,
                        expires_at = expiresAt,
                    });
                }

                var codeText = code.ToString(this.verifyCodeFormat);
                if (scrubbedContact.Contains("@")) {
                    await this.onSendEmailVerifyCode(scrubbedContact, codeText);
                }
                else {
                    await this.onSendPhoneVerifyCode(scrubbedContact, codeText);
                }

                await transaction.CommitAsync();
            }
        }

        public async Task VerifyAsync(Dict data) {
            if (!data.ContainsKey("email") && !data.ContainsKey("phone")) throw new Exception("Must specify an email or phone verify code");

            string userId = data.GetAs("user_id", "");
            if (string.IsNullOrEmpty(userId)) throw new Exception("Must specify a user id");
            Dict user = await this.database.SelectRowAsync($"SELECT {this.userTableEmailFieldName}, {this.userTablePhoneFieldName} FROM {this.userTableName}", userId);
            if (user == null) throw new Exception($"Invalid user id '{userId}'");

            var updateValues = new Dict {
                { this.userTableIdFieldName, userId },
            };

            int emailVerifyCode = data.GetAs("email", -1);
            if (emailVerifyCode > 0) {
                var email = user.GetAs(this.userTableEmailFieldName, "");
                await this.VerifyAsync(email, emailVerifyCode);
                updateValues[this.userTableEmailVerifiedAtFieldName] = DateTime.Now;
            }

            int phoneVerifyCode = data.GetAs("phone", -1);
            if (phoneVerifyCode > 0) {
                var phone = user.GetAs(this.userTablePhoneFieldName, "");
                await this.VerifyAsync(phone, phoneVerifyCode);
                updateValues[this.userTablePhoneVerifiedAtFieldName] = DateTime.Now;
            }

            await database.UpdateAndCommitAsync(this.userTableName, updateValues);

            if (this.onVerified != null) this.onVerified(data);
        }

        /*
        /// <summary>
        /// Call to verify a user's email or phone
        /// </summary>
        /// <param name="transaction"></param>
        /// <param name="userId"></param>
        /// <param name="verifyCode"></param>
        /// <param name="verifyCodeFieldName"></param>
        /// <param name="verifiedAtFieldName"></param>
        /// <returns></returns>
        public async Task VerifyAsync(ITransaction transaction, string userId, int verifyCode, string verifyCodeFieldName, string verifiedAtFieldName) {

            Dict data = await this.database.SelectRowAsync($"SELECT verify_code, expires_at FROM {this.sendVerifyTableName}", new {
                contact
            });
            if (userVerifyCode != verifyCode) throw new Exception("Verify code is incorrect");

            var values = new Dict {
                { this.userTableIdFieldName, userId },
                { verifiedAtFieldName, DateTime.Now }
            };
            await transaction.UpdateAsync(this.userTableName, values);
        }
        */
        
        protected async Task VerifyAsync(string contact, int code) {
            logger.Debug($"VerifyAsync():contact={contact},code={code}");
            string scrubbedContact = Validate(contact);
            Dict result = await this.database.SelectRowAsync($"SELECT verify_code, expires_at FROM {this.sendVerifyTableName}", new {
                contact = scrubbedContact
            });
            int verifyCode = result.GetAs("verify_code", -1);
            if (code == -1 || code != verifyCode) throw new Exception("Invalid contact and/or verify code");

            int expiresAtUnix = result.GetAs("expires_at", -1);
            if (DateTimeX.FromUnixTimestamp(expiresAtUnix) < DateTime.Now) throw new Exception("Expired verify code");
        }

        protected static string Validate(string value) {
            logger.Debug($"Validate():value={value}");
            if (value.Contains("@")) {
                return EMAIL_FIELD_VALIDATOR.Validate(value);
            }
            else {
                return PHONE_FIELD_VALIDATOR.Validate(value);
            }
        }


        /// <summary>
        /// Registers a new user
        /// </summary>
        /// <param name="input"></param>
        /// <param name="notifyData"></param>
        /// <returns></returns>
        public async Task<UserRefToken> RegisterAsync(dynamic input, Dict notifyData = null) {
            Dict registration = this.ConvertInputToDict(input);

            // Lookup existing user, account, and username
            string existingUserId = registration.GetAs("user_id", (string)null);
            string existingAccountId = null;
            string existingUsername = null;
            logger.Trace($"RegisterAsync():existingUserId={existingUserId}");
            if (!string.IsNullOrEmpty(existingUserId)) {
                Dict row = await this.database.SelectRowAsync($"SELECT {this.userTableAccountIdFieldName}, {this.userTableUsernameFieldName} FROM {this.userTableName}", existingUserId);
                existingAccountId = row.GetAs(this.userTableAccountIdFieldName, "");
                existingUsername = row.GetAs(this.userTableUsernameFieldName, "");
            }

            // Validate username
            string username = this.usernameFieldValidator.Validate(registration?.GetAs(this.userTableUsernameFieldName, (string)null));
            logger.Trace($"RegisterAsync():username={username}");
            if (username != existingUsername) {
                Dict existingUserByUsername = await this.database.SelectRowAsync(this.userTableName, new Dict {
                    { this.userTableUsernameFieldName, username }
                });
                if (existingUserByUsername != null) throw new Exception("Username '" + username + "' is unavailable");
            }

            // Validate password
            string password = this.passwordFieldValidator.Validate(registration?.GetAs("password", (string)null));

            // Validate email and phone
            string email = this.emailFieldValidator.Validate(registration?.GetAs(this.userTableEmailFieldName, (string)null));
            string phone = this.phoneFieldValidator.Validate(registration?.GetAs(this.userTablePhoneFieldName, (string)null));

            // Validate first and last name
            string firstName = this.nameFieldValidator.Validate(registration?.GetAs(this.userTableFirstNameFieldName, (string)null));
            string lastName = this.nameFieldValidator.Validate(registration?.GetAs(this.userTableLastNameFieldName, (string)null));

            string role = string.IsNullOrEmpty(this.userTableRoleFieldName) ? this.defaultRole : registration?.GetAs(this.userTableRoleFieldName, this.defaultRole);

            // Create salt and password hash
            string salt = Guid.NewGuid().ToString();
            string passwordHash = $"{salt} {password}".Hash();

            // Create account
            string accountId;
            using (ITransaction transaction = await this.database.BeginTransactionAsync()) {
                if (string.IsNullOrEmpty(existingAccountId)) {
                    var extraAccountInfo = this.getExtraAccountInfo == null ? null : this.getExtraAccountInfo(registration);
                    accountId = await transaction.InsertAsync<string>(this.accountTableName, extraAccountInfo);
                }
                else {
                    accountId = existingAccountId;
                }

                // Create user record
                Dict user = new Dict {
                    { this.userTableAccountIdFieldName, accountId },
                    { this.userTableUsernameFieldName, username },
                    { this.userTableSaltFieldName, salt },
                    { this.userTablePasswordHashFieldName, passwordHash },
                    { this.userTableEmailFieldName, email },
                    { this.userTablePhoneFieldName, phone },
                    { this.userTableFirstNameFieldName, firstName  },
                    { this.userTableLastNameFieldName, lastName },
                };
                if (!string.IsNullOrEmpty(this.userTableRoleFieldName) && !string.IsNullOrEmpty(this.defaultRole)) {
                    user[this.userTableRoleFieldName] = role;
                }
                Dict extraUserInfo = this.getExtraUserInfo == null ? null : this.getExtraUserInfo(registration);
                if (extraUserInfo != null) {
                    user.UpdateFrom(extraUserInfo);
                }

                string userId;
                if (string.IsNullOrEmpty(existingUserId)) {
                    userId = await transaction.InsertAsync<string>(this.userTableName, user);
                }
                else {
                    userId = existingUserId;
                    user[this.userTableIdFieldName] = userId;
                    await transaction.UpdateAsync(this.userTableName, user);
                }

                if (this.onRegister != null) {
                    transaction.OnCommit(async () => {
                        var registerUser = new Dict {
                            { this.userTableIdFieldName, userId },
                            { this.userTableAccountIdFieldName, accountId },
                            { this.userTableUsernameFieldName, username },
                            { this.userTableEmailFieldName, email },
                            { this.userTablePhoneFieldName, phone },
                            { this.userTableFirstNameFieldName, firstName  },
                            { this.userTableLastNameFieldName, lastName },
                        };
                        if (notifyData != null) registerUser.UpdateFrom(notifyData);
                        try {
                            await this.onRegister(string.IsNullOrEmpty(existingAccountId), registerUser);
                        }
                        catch (Exception e) {
                            logger.Debug(e);
                        }
                    });
                }

                UserRefToken userRefToken = await this.CreateUserRefTokenAsync(transaction, userId, username, role, accountId);
                await transaction.CommitAsync();

                return userRefToken;
            }
        }

        /// <summary>
        /// Validates the auth token id returning an <see cref="AuthToken"/> instance
        /// </summary>
        /// <param name="authType"></param>
        /// <param name="authValue"></param>
        /// <returns>An <see cref="AuthToken"/> instance</returns>
        public Task<AuthToken> AuthenticateAsync(string authType, string authValue) {
            if (!this.authenticatorByType.TryGetValue(authType, out IAuthenticator authenticator)) throw new Exception($"Unknown auth type {authType}");
            return authenticator.AuthenticateAsync(authType, authValue);
        }

        /// <summary>
        /// Lookup user record from username
        /// </summary>
        /// <param name="username"></param>
        /// <param name="fieldNames"></param>
        /// <returns></returns>
        public async Task<Dict> LookupUsernameAsync(string username, string fieldNames = "*") {
            username = this.usernameFieldValidator.Validate(username);
            string sql = $"SELECT {fieldNames} FROM {this.userTableName} WHERE {this.userTableUsernameFieldName}=@username";
            logger.Trace($"LookupUsername():sql={sql}");
            return await this.database.SelectRowAsync(sql, new {
                username
            });
        }

        /// <summary>
        /// Creates an anonymous user and returns a valid <see cref="AuthToken"/>
        /// </summary>
        /// <returns>An  <see cref="AuthToken"/> instance created</returns>
        public async Task<AuthToken> CreateAnonymousUserAsync() {
            Random random = new Random();
            using (ITransaction transaction = await this.database.BeginTransactionAsync()) {
                string accountId = await transaction.InsertAsync<string>(this.accountTableName);
                string role = this.defaultRole;

                var firstName = CleverNameX.COLORS[random.Next(0, CleverNameX.COLORS.Length)];
                var lastName = CleverNameX.ANIMALS[random.Next(0, CleverNameX.ANIMALS.Length)];
                Dict user = new Dict {
                    { this.userTableFirstNameFieldName, firstName },
                    { this.userTableLastNameFieldName, lastName },
                    { this.userTableAccountIdFieldName, accountId },
                };
                if (!string.IsNullOrEmpty(this.userTableRoleFieldName) && !string.IsNullOrEmpty(role)) {
                    user[this.userTableRoleFieldName] = role;
                }
                string userId = await transaction.InsertAsync<string>(this.userTableName, user);

                DateTime expiresAt = DateTime.Now.AddDays(this.authTokenDurationDays);
                string id = await this.userRefTokenAuthenticator.InsertAsync(transaction, userId, expiresAt);

                await transaction.CommitAsync();

                return new UserRefToken(id, userId, null, role, accountId, expiresAt);
            }
        }

        /// <summary>
        /// Create an auth token
        /// </summary>
        /// <param name="userId"></param>
        /// <returns>The AuthToken instance created</returns>
        public async Task<UserRefToken> CreateUserRefTokenAsync(string userId) {
            List<string> fieldNames = new List<string>();
            if (!string.IsNullOrEmpty(this.userTableUsernameFieldName)) fieldNames.Add(this.userTableUsernameFieldName);
            if (!string.IsNullOrEmpty(this.userTableRoleFieldName)) fieldNames.Add(this.userTableRoleFieldName);
            if (!string.IsNullOrEmpty(this.userTableAccountIdFieldName)) fieldNames.Add(this.userTableAccountIdFieldName);
            Dict user = await this.database.SelectRowAsync($"SELECT {string.Join(",", fieldNames)} FROM user WHERE id=@userId", new {
                userId
            });
            if (user==null) throw new Exception("Invalid user");

            UserRefToken userRefToken;
            using (ITransaction transaction = await this.database.BeginTransactionAsync()) {
                DateTime expiresAt = DateTime.Now.AddDays(this.authTokenDurationDays);
                string username = string.IsNullOrEmpty(this.userTableUsernameFieldName) ? null : user.GetAs(this.userTableUsernameFieldName, (string)null);
                string role = string.IsNullOrEmpty(this.userTableRoleFieldName) ? null : user.GetAs(this.userTableRoleFieldName, (string)null);
                string accountId = string.IsNullOrEmpty(this.userTableAccountIdFieldName) ? null : user.GetAs(this.userTableAccountIdFieldName, (string)null);
                userRefToken = await this.CreateUserRefTokenAsync(transaction, userId, username, role, accountId);

                await transaction.CommitAsync();
            }

            return userRefToken;
        }

        protected async Task<UserRefToken> CreateUserRefTokenAsync(ITransaction transaction, string userId, string username, string role, string accountId) {
            DateTime expiresAt = DateTime.Now.AddDays(this.authTokenDurationDays);
            string id = await this.userRefTokenAuthenticator.InsertAsync(transaction, userId, expiresAt);
            return new UserRefToken(id, userId, username, role, accountId, expiresAt);
        }

        /// <summary>
        /// Logs in the user creating a valid <see cref="AuthToken"/>
        /// </summary>
        /// <param name="login"></param>
        /// <returns></returns>
        public async Task<UserRefToken> LoginAsync(Dict login) {
            string username = login?.GetAs(this.userTableUsernameFieldName, (string)null);
            Dict user = await this.LookupUsernameAsync(username, string.Join(",", new string[] { this.userTableIdFieldName, this.userTableSaltFieldName, this.userTablePasswordHashFieldName }));
            if (user == null) throw new Exception("Invalid username '" + username + "'");

            string passwordHash = user.GetAs(this.userTablePasswordHashFieldName, (string)null);

            string salt = user.GetAs(this.userTableSaltFieldName, (string)null);
            string password = this.passwordFieldValidator.Validate(login?.GetAs("password", (string)null));
            string newPasswordHash = $"{salt} {password}".Hash();

            if (newPasswordHash != passwordHash) throw new Exception("Incorrect password");

            string userId = user.GetAs(this.userTableIdFieldName, (string)null);
            return await this.CreateUserRefTokenAsync(userId);
        }

        /// <summary>
        /// Creates a reset code and invokes <see cref="AuthManager.onForgotPassword"/> to send the reset code to the user
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        public async Task ForgotPasswordAsync(string username) {
            Dict user = await this.LookupUsernameAsync(username, string.Join(",", new string[] { this.userTableIdFieldName, this.userTableFirstNameFieldName, this.userTableLastNameFieldName, this.userTableEmailFieldName }));
            if (user == null) throw new Exception("Invalid username '" + username + "'");

            string userId = user.GetAs(this.userTableIdFieldName, (string)null);
            string resetCode = await this.CreateResetCodeAsync(userId);
            user[this.userTableResetCodeFieldName] = resetCode;

            if (this.onForgotPassword != null) this.onForgotPassword(user);
        }

        /// <summary>
        /// Resets the user's password if a valid reset code is included
        /// </summary>
        /// <param name="resetPassword"></param>
        /// <returns></returns>
        public async Task<AuthToken> ResetPasswordAsync(Dict resetPassword) {
            string username = resetPassword.GetAs(this.userTableUsernameFieldName, (string)null);
            Dict user = await this.database.SelectRowAsync(this.userTableName, new Dict {
                { this.userTableUsernameFieldName, username }
            });
            if (user == null) throw new Exception("Invalid username '" + username + "'");

            string userResetCode = user.GetAs(this.userTableResetCodeFieldName, (string)null);
            string resetCode = resetPassword.GetAs(this.userTableResetCodeFieldName, (string)null);
            if (!userResetCode.Equals(resetCode, StringComparison.OrdinalIgnoreCase)) throw new Exception("Invalid reset code '" + resetCode + "'");

            DateTime expiresAt = user.GetAs(this.userTableResetCodeExpiresAtFieldName, DateTime.MinValue);
            if (expiresAt==DateTime.MinValue || expiresAt < DateTime.Now) throw new Exception("Reset code has expired");

            string userId = user.GetAs(this.userTableIdFieldName, (string)null);
            string salt = user.GetAs(this.userTableSaltFieldName, (string)null);
            string password = this.passwordFieldValidator.Validate(resetPassword?.GetAs("password", (string)null));
            string passwordHash = $"{salt} {password}".Hash();

            Dict update = new Dict {
                { this.userTableIdFieldName, userId },
                { this.userTablePasswordHashFieldName, passwordHash },
            };
            await this.database.UpdateAndCommitAsync(this.userTableName, update);

            return await this.CreateUserRefTokenAsync(userId);
        }

        /// <summary>
        /// Invokes <see cref="AuthManager.onForgotUsername"/> with a list of matching usernames
        /// </summary>
        /// <param name="contact"></param>
        /// <returns></returns>
        public async Task ForgotUsernameAsync(string contact) {
            if (string.IsNullOrEmpty(contact)) throw new Exception("Contact cannot be null");

            string newContact;
            string[] usernames;
            if (contact.Contains("@")) {
                newContact = this.emailFieldValidator.Validate(contact);
                usernames = await this.database.SelectValuesAsync<string>($"SELECT {this.userTableUsernameFieldName} FROM {this.userTableName} WHERE {this.userTableEmailFieldName}=@newContact", new {
                    newContact
                });
            }
            else {
                newContact = this.phoneFieldValidator.Validate(contact);
                usernames = await this.database.SelectValuesAsync<string>($"SELECT {this.userTableUsernameFieldName} FROM {this.userTableName} WHERE {this.userTablePhoneFieldName}=@newContact", new {
                    newContact
                });
            }

            string usernamesText = "";
            if (usernames!=null) {
                usernamesText = string.Join(",", usernames.Where(x => !string.IsNullOrEmpty(x)));
            }
            if (this.onForgotUsername != null) this.onForgotUsername(new Dict {
                ["contact"] = newContact,
                ["usernames"] = usernamesText
            });
        }

        protected async Task<string> CreateResetCodeAsync(string userId) {
            Random random = new Random();
            int resetCodeMax = (int)Math.Pow(10, this.resetCodeLength);
            long randomResetCode = random.Next(resetCodeMax);
            var resetCode = randomResetCode.ToString(String.Concat(Enumerable.Repeat("0", this.resetCodeLength)));

            DateTime expiresAt = DateTime.Now.AddMinutes(this.resetTokenDurationMinutes);
            await this.database.UpdateAndCommitAsync(this.userTableName, new Dict {
                { this.userTableIdFieldName, userId },
                { this.userTableResetCodeFieldName, resetCode },
                { this.userTableResetCodeExpiresAtFieldName, expiresAt },
            });

            return resetCode;
        }

        protected Dict ConvertInputToDict(dynamic input) {
            // If is null, return empty dictionary
            if (input == null) {
                return new Dict();
            }

            // If is already a dictionary, return the dictionary
            else if (input is Dict d) {
                return new Dict(d);
            }

            // Otherwise, convert input to a dictionary
            else {
                return DynamicX.ToDictionary(input);
            }
        }

        public async Task<UserRefToken> GetUserRefToken(IWebRequest req) {
            var authentication = req.GetAuthenticationHeaderValue();
            UserRefToken userRefToken = await this.AuthenticateAsync(authentication?.Scheme, authentication?.Parameter) as UserRefToken;
            if (userRefToken == null) throw new UnauthorizedException();
            return userRefToken;
        }
    }

    /// <summary>
    /// Represents the result of a successful <see cref="AuthManager.LoginAsync(Dict)"/> or <see cref="AuthManager.RegisterAsync(dynamic, Dict)"/>
    /// </summary>
    public abstract class AuthToken {
        public readonly string type;
        public readonly string accountId;
        public readonly string role;

        public AuthToken(string type, string accountId, string role) {
            this.type = type;
            this.accountId = accountId;
            this.role = role;
        }
    }

}

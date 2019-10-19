# Butterfly.Auth ![Butterfly Logo](https://raw.githubusercontent.com/firesharkstudios/Butterfly/master/img/logo-40x40.png) 

> Authenticate clients in C# using Butterfly.Db and Butterfly.Web

# Install from Nuget

| Name | Package | Install |
| --- | --- | --- |
| Butterfly.Auth | [![nuget](https://img.shields.io/nuget/v/Butterfly.Auth.svg)](https://www.nuget.org/packages/Butterfly.Auth/) | `nuget install Butterfly.Auth` |

# Install from Source Code

```git clone https://github.com/firesharkstudios/butterfly-auth```

# Getting Started

## Creating an *AuthManager* instance

Normally, you will create a single instance of *AuthManager*. *AuthManager* only requires passing in an *IDatabase* instance; 
however, the following pattern is useful to get an *AuthManager*
that verifies emails, verifies phone numbers, sends welcome emails,
sends forgot password emails, etc.

```cs
var database = (initialize an IDatabase instance here)
var sendMessageQueueManager = (initialize SendMessageQueueManager here)
var welcomeEmailSendMessage = (load welcome email here)
var resetEmailSendMessage = (load reset email here)
var authManager = new AuthManager(
    database,
    onEmailVerify: sendMessageQueueManager.VerifyAsync,
    onPhoneVerify: sendMessageQueueManager.VerifyAsync,
    onRegister: user => {
        sendMessageQueueManager.Queue(welcomeEmailSendMessage.Evaluate(user));
    },
    onForgotPassword: user => {
        sendMessageQueueManager.Queue(resetEmailSendMessage.Evaluate(user));
    }
);
```

See [Butterfly.Db](https://github.com/firesharkstudios/butterfly-db) and [Butterfly.Message](https://github.com/firesharkstudios/butterfly-message)
for more information.

## Database Structure

Butterfly.Auth requires [Butterfly.Db](https://github.com/firesharkstudios/butterfly-db) 
to manage authentication tokens, users, and accounts.

While you can use any database engine supported by [Butterfly.Db](https://github.com/firesharkstudios/butterfly-db), 
here is the SQL to create the necessary tables in MySQL...

```
CREATE TABLE account (
    id VARCHAR(50) NOT NULL,
    created_at INT NOT NULL,
    updated_at INT NOT NULL,
    PRIMARY KEY(id)
);

CREATE TABLE user(
    id VARCHAR(50) NOT NULL,
    account_id VARCHAR(50) NOT NULL,
    username VARCHAR(40) NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    email_verified_at INT NULL,
    phone VARCHAR(20) NULL,
    phone_verified_at INT NULL,
    salt VARCHAR(40) NOT NULL,
    password_hash VARCHAR(90) NOT NULL,
    reset_code VARCHAR(6) NULL,	
    reset_code_expires_at INT NULL,	
    created_at INT NOT NULL,
    updated_at INT NOT NULL,
    PRIMARY KEY(id),
    UNIQUE INDEX username(username)
);

CREATE TABLE auth_token(
    id VARCHAR(50) NOT NULL,
    user_id VARCHAR(50) NOT NULL,
    expires_at INT NOT NULL,
    created_at INT NOT NULL,
    PRIMARY KEY(id)
);
```

# Auth Web Api

Calling *AuthManager.SetupWebApi()* creates a web API that allows clients to
make the following requests...

## GET /api/auth/check-username/\{username\}

Returns true/false if the username is available

## GET /api/auth/check-user-ref-token/\{id\}

Returns true/false if the previously issues user ref token is valid

## POST /api/auth/create-anonymous

Creates an anonymous user (no username) assigning the user random first and last names

## POST /api/auth/register

Registers a user (requires email, phone, and password fields)

Returns a valid user ref token

## POST /api/auth/login

Logs in a user (requires username and password fields)

Returns a valid user ref token

## POST /api/auth/forgot-password

Invokes the *forgotPasswordAsync* function passed to the constructor of *AuthManager* (normally sends a reset password email)

## POST /api/auth/reset-password

Resets a user's password

## POST /api/auth/forgot-username

Invokes the forgotUsernameAsync function passed to the constructor of *AuthManager* (normally sends a forgot username email)

## POST /api/auth/verify-email

Invokes the *verifyAsync* function passed to the constructor of *AuthManager* (normally sends a verify email)

## POST /api/auth/verify-phone

Invokes the *verifyAsync* function passed to the constructor of *AuthManager* (normally sends a verify text)


# Contributing

If you'd like to contribute, please fork the repository and use a feature
branch. Pull requests are warmly welcome.

# Licensing

The code is licensed under the [Mozilla Public License 2.0](http://mozilla.org/MPL/2.0/).  

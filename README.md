# GoogleOAuth2Kit

## Description

GoogleOAuth2Kit is a Deno library that provides abstractions for simplifying Google API authentication. It handles the entire authentication flow, including generating an authentication URL, retrieving the authorization code, exchanging it for an access token, handling refresh tokens, and managing errors. With GoogleOAuth2Kit, developers can seamlessly authenticate with Google APIs without worrying about the intricacies of the authentication process.

## Features

- Generates authentication URL
- Retrieves authorization code
- Exchanges authorization code for access token
- Handles refresh tokens
- Error handling with detailed diagnostics

## Prerequisites

Before using GoogleOAuth2Kit, ensure you have the following prerequisites installed:

- Deno (version 1.40 or higher)

## Pre-Usage Requirements

- Rename .env.google.example to .env.google
- Fill your **client_id, client_secret** and list of **scopes** obtained from Google

## Usage

```js
import GoogleOAuth2Kit from "https://deno.land/x/googleoauth2kit@v1.1.0/mod.ts";

const envPath = "./.env.google";

const googleoauth2kit = await new GoogleOAuth2Kit(envPath);
const oauth2Client = googleoauth2kit.oauth2Client;
```

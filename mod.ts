import * as dotenv from "https://deno.land/std@0.218.2/dotenv/mod.ts";
import { Credentials, OAuth2Client } from "npm:google-auth-library";
import { existsSync } from "https://deno.land/std@0.219.1/fs/mod.ts";
type TJSONEnv = {
  client_id: string;
  client_secret: string;
  redirect_uris: Array<string>;
  scopes: Array<string>;

  access_token: string | undefined | null;
  refresh_token: string | undefined | null;
  token_type: string | undefined | null;
  expiry_date: number | undefined | null;
};

export default class GoogleOAuth2Kit {
  private envPath: string;
  private readonly availableScopes: string[] = [
    "https://www.googleapis.com/auth/youtube",
    "https://www.googleapis.com/auth/youtube.channel-memberships.creator",
    "https://www.googleapis.com/auth/youtube.readonly",
    "https://www.googleapis.com/auth/youtube.force-ssl",
    "https://www.googleapis.com/auth/youtube.upload",
    "https://www.googleapis.com/auth/youtubepartner",
    "https://www.googleapis.com/auth/youtubepartner-channel-audit",
  ];
  private readonly requiredEnvKeys: string[] = [
    "client_id",
    "client_secret",
    "redirect_uris",
    "scopes",
  ];

  private envAsJSON: TJSONEnv | undefined;
  private oauth2Client: OAuth2Client | undefined;

  constructor(envPath: string = "./.env.google") {
    this.envPath = envPath;

    try {
      const envExists = existsSync(envPath);
      if (!envExists) throw new Error("Error: .env file not found.");
      const env = Deno.readTextFileSync(this.envPath);
      const jsonEnvRecord: Record<string, string> = dotenv.parse(env);
      this.envAsJSON = this.parseRecordToJSON(jsonEnvRecord);
      // Check if required keys are present in .env file
      this.checkEnv(this.envAsJSON, this.requiredEnvKeys);
      // Check if passed scopes are valid
      this.checkScopes(this.envAsJSON.scopes, this.availableScopes);
      // Authorize
      // @ts-ignore <Returning the expected behaviour as long as await is used on the constructor>
      return Promise.resolve(this.authorize(this.envAsJSON)).then(
        (oauth2Client) => {
          this.oauth2Client = oauth2Client;
          return this;
        }
      );
    } catch (error) {
      console.error(error);
      if (error.cause) console.error(error.cause);
      return error;
    }
  }

  parseRecordToJSON(jsonEnvRecord: Record<string, string>) {
    const jsonEnv: TJSONEnv = {
      client_id: jsonEnvRecord.client_id,
      client_secret: jsonEnvRecord.client_secret,
      redirect_uris: jsonEnvRecord.redirect_uris.split(","),
      access_token: jsonEnvRecord?.access_token,
      refresh_token: jsonEnvRecord?.refresh_token,
      scopes: jsonEnvRecord.scopes.split(","),
      token_type: jsonEnvRecord?.token_type,
      expiry_date: Number(jsonEnvRecord?.expiry_date),
    };
    return jsonEnv;
  }

  parseJSONToRecord(jsonEnv: TJSONEnv) {
    const jsonEnvRecord: Record<string, string> = {
      client_id: jsonEnv.client_id,
      client_secret: jsonEnv.client_secret,
      redirect_uris: jsonEnv.redirect_uris.join(","),
      access_token: jsonEnv?.access_token as string,
      refresh_token: jsonEnv?.refresh_token as string,
      scopes: jsonEnv.scopes.join(","),
      token_type: jsonEnv?.token_type as string,
      expiry_date: String(jsonEnv?.expiry_date),
    };
    return jsonEnvRecord;
  }

  checkEnv(jsonEnv: TJSONEnv, requiredEnvKeys: string[]) {
    for (const key of requiredEnvKeys) {
      if (!jsonEnv[key as keyof TJSONEnv]) {
        throw new Error(`Error: ${key} not found in .env file.`);
      }
    }
    return true;
  }

  checkScopes(scopes: string[], availableScopes: string[]) {
    for (const scope of scopes) {
      if (!availableScopes.includes(scope))
        throw new Error(`Error: ${scope} is not a valid scope.`);
    }
    return true;
  }

  checkIfAuthenticatedBefore(jsonEnv: TJSONEnv) {
    if (
      jsonEnv.access_token &&
      jsonEnv.refresh_token &&
      jsonEnv.expiry_date &&
      jsonEnv.token_type &&
      jsonEnv.scopes
    ) {
      return true;
    } else return false;
  }

  //Not Pure Function
  async authorize(jsonEnv: TJSONEnv) {
    try {
      const clientId = jsonEnv.client_id;
      const clientSecret = jsonEnv.client_secret;
      const redirectUrl = jsonEnv.redirect_uris[0];

      this.oauth2Client = new OAuth2Client(clientId, clientSecret, redirectUrl);

      if (
        !this.checkIfAuthenticatedBefore(jsonEnv) ||
        (jsonEnv.expiry_date && jsonEnv.expiry_date < new Date().getTime())
      ) {
        await this.getNewToken(this.oauth2Client, jsonEnv);
      } else {
        this.oauth2Client.credentials = jsonEnv;
      }
      return this.oauth2Client;
    } catch (error) {
      return error;
    }
  }

  checkCode(oauth2Client: OAuth2Client, reqUrl: string, jsonEnv: TJSONEnv) {
    try {
      const code = new URL(reqUrl).searchParams.get("code");
      if (!code) throw new Error("Error: Code not found in the URL.");
      oauth2Client.getToken(String(code), (err, token) => {
        if (err)
          throw new Error("Error while trying to retrieve access token", err);
        else if (token) {
          oauth2Client.setCredentials(token);
          this.storeToken(token, jsonEnv);
        } else throw new Error("Error: Access token is undefined.");
      });
      return true;
    } catch (error) {
      console.error(error);
      return error;
    }
  }

  async getNewToken(oauth2Client: OAuth2Client, jsonEnv: TJSONEnv) {
    try {
      const authUrl = oauth2Client.generateAuthUrl({
        access_type: "offline",
        scope: jsonEnv.scopes,
      });

      console.log("Authorize this app by visiting this url: ", authUrl);
      const hostname = jsonEnv.redirect_uris[0].split("//")[1].split(":")[0];
      const port = Number(jsonEnv.redirect_uris[0].split(":")[2].split("/")[0]);

      let server: Deno.HttpServer = {} as Deno.HttpServer;
      await new Promise((resolve, reject) => {
        server = Deno.serve({ port, hostname }, (req) => {
          console.log("Waiting for response...");
          if (this.checkCode(oauth2Client, req.url, jsonEnv)) {
            resolve(req);
            return new Response("Authorization Sucessful");
          } else {
            reject(req);
            return new Response(
              "Error: Something went wrong while trying to authorize the app."
            );
          }
        });
      });
      server.shutdown();
    } catch (error) {
      return error;
    }
  }

  storeToken(token: Credentials, jsonEnv: TJSONEnv) {
    jsonEnv.access_token = token.access_token;
    jsonEnv.refresh_token = token.refresh_token;
    jsonEnv.token_type = token.token_type;
    jsonEnv.expiry_date = token.expiry_date;
    jsonEnv.scopes = token.scope?.split(",") as string[];

    Deno.writeTextFileSync(
      this.envPath,
      dotenv.stringify(this.parseJSONToRecord(jsonEnv))
    );
  }
}

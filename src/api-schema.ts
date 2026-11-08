// Arguments of an api_request call. Shared by the api_request tool and run_code's api.request(), so code in the sandbox
// is validated exactly like a tool call (and can never set the server-only fields in api-call.ts's Internal).
import { z } from "zod";

export const secretName = z.string().min(1).regex(/^(vault:)?[A-Za-z0-9_.\-]+$/, "letters, digits, _ . - only (or vault:<name>)");

export const apiRequestShape = {
  url: z.string().min(8).describe("Full https:// URL (may contain {{vault:name}})"),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).default("GET"),
  headers: z.record(z.string(), z.string()).optional().describe("Extra request headers (e.g. Notion-Version, Accept)"),
  query: z.record(z.string(), z.string()).optional().describe("Query string params"),
  body: z.union([z.string(), z.record(z.string(), z.unknown()), z.array(z.unknown())]).optional().describe("Request body; objects/arrays are sent as JSON"),
  body_base64: z.string().optional().describe("Raw binary request body as base64 (max 5 MB decoded), e.g. PUT an object to S3. Set Content-Type in headers. Use instead of body."),
  body_source: z.string().optional().describe("Send a file stored with get_upload_url as the raw request body: pass its download URL (or key). The server reads it and forwards it, so the bytes never pass through the chat (max 40 MB). Use instead of body_base64."),
  multipart: z.object({
    fields: z.record(z.string(), z.string()).optional().describe("Plain form fields, sent before the files"),
    files: z.array(z.object({
      field: z.string().default("file").describe("Form field name, default 'file'"),
      filename: z.string().optional().describe("File name; required with data_base64, defaults to the stored name with source"),
      content_type: z.string().optional().describe("e.g. image/png; defaults to the stored file's type with source"),
      data_base64: z.string().optional().describe("File bytes as base64 (max 5 MB). Use this OR source."),
      source: z.string().optional().describe("Download URL (or key) of a file stored with get_upload_url; the server reads it itself (max 40 MB total). Use this OR data_base64."),
    })).min(1),
  }).optional().describe("multipart/form-data upload (max 5 MB total with data_base64, 40 MB with source), e.g. Notion /v1/file_uploads/{id}/send. Use instead of body."),
  auth_type: z.enum(["bearer", "header", "basic", "query", "oauth2_refresh", "aws"]).optional().describe("Default bearer; OAuth refresh-token secrets (e.g. GOOGLE_OAUTH) use oauth2_refresh and AWS secrets use aws automatically"),
  secret: secretName.describe("Name of the secret holding the token / API key (for oauth2_refresh: the OAuth secret, e.g. GOOGLE_OAUTH), or a vault handle vault:<name>"),
  aws_service: z.string().regex(/^[a-z0-9-]{2,40}$/).optional().describe("AWS only: signing service name (s3, dynamodb, ssm, logs, ec2, ...). Guessed from the host when left out."),
  aws_region: z.string().regex(/^[a-z]{2}(-[a-z]+)+-\d$/).optional().describe("AWS only: region, e.g. ap-south-1. Guessed from the host, then the secret."),
  capture: z.record(z.string().regex(/^[A-Za-z0-9_-]{1,64}$/), z.string().max(200)).optional().describe("Keep values from the response server-side instead of showing them: {name: JSON path like $.key or $.data[0].token}. The response shows vault:<name> in their place; use it later as secret or {{vault:name}} in a header, URL or body."),
  capture_minutes: z.number().int().min(1).max(1440).optional().describe("How long captured values live (default 60)"),
  header_name: z.string().optional(),
  header_prefix: z.string().optional(),
  query_param: z.string().optional(),
  username: z.string().optional(),
  save_response: z.boolean().optional().describe("Store a successful (2xx) response body in temporary storage and return saved.download_url instead of the body. Use for binary output such as text-to-speech audio, images or file downloads. Error responses are returned as text as usual."),
  path: z.string().optional().describe("Folder of the secret, e.g. /notion. If omitted, the secret is found by name in any folder (an error if the name exists in several)."),
  environment: z.string().optional().describe("Environment slug (default from config, e.g. dev)"),
};
export const apiRequestSchema = z.object(apiRequestShape);

import { connectDb } from "@/lib/mongodb";
import { verifyFirebaseToken } from "@/lib/firebase-admin";
import { jsonError, jsonSuccess } from "@/lib/api-response";

export const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const MAX_ATTEMPTS = 10;

export async function GET(request) {
  try {
    // 1. Rate Limiting Check
    const ip = request.headers.get("x-forwarded-for") || "127.0.0.1";
    const now = Date.now();
    
    if (!rateLimitMap.has(ip)) {
      rateLimitMap.set(ip, []);
    }
    
    const attempts = rateLimitMap.get(ip).filter((timestamp) => now - timestamp < RATE_LIMIT_WINDOW);
    attempts.push(now);
    rateLimitMap.set(ip, attempts);

    if (attempts.length > MAX_ATTEMPTS) {
      console.warn(`[Rate Limit] Labels fetch rate limit exceeded for IP: ${ip} at ${new Date(now).toISOString()}`);
      return jsonError("Too many attempts. Please try again later.", 429);
    }

    // 2. Token Authentication Check
    const authorization = request.headers.get("authorization");
    const token = authorization?.split(" ")[1];

    if (!token) {
      return jsonError("Unauthorized: No token provided", 401);
    }

    const decodedToken = await verifyFirebaseToken(token);

    if (!decodedToken) {
      return jsonError("Unauthorized: Invalid token", 401);
    }

    // 3. Fetch Data with Projection, Search Filtering & Bounded Results
    const { searchParams } = new URL(request.url);
    const search = searchParams.get("search")?.trim() || "";

    const query = search
      ? {
          $or: [
            { name: { $regex: search, $options: "i" } },
            { email: { $regex: search, $options: "i" } },
          ],
        }
      : {};

    const db = await connectDb();
    const users = db.collection("users");

    const allUsers = await users
      .find(query, { projection: { _id: 0, name: 1, email: 1, image: 1 } })
      .limit(50)
      .toArray();

    return jsonSuccess(allUsers, 200);
  } catch (err) {
    console.error("❌ Error fetching labels:", err);
    return jsonError("Failed to fetch labels", 500);
  }
}
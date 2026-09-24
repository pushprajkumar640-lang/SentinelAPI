export const FOOD_DELIVERY_OPENAPI_SPEC = {
  openapi: "3.0.3",
  info: {
    title: "FoodDelivery Sandbox API",
    version: "1.0.0",
    description: "Authorized Sandbox & Test Target for SentinelAPI Security Assessment. Contains intentionally sandboxed vulnerability testbeds for BOLA/IDOR, Excessive Data Exposure, and Weak Rate Limiting evaluation.",
    contact: {
      name: "Security QA Team",
      email: "security-sandbox@internal.test"
    }
  },
  servers: [
    {
      url: "http://127.0.0.1:3000/api/sandbox",
      description: "Local Isolated Security Sandbox (Authorized Target Only)"
    }
  ],
  security: [
    {
      BearerAuth: []
    }
  ],
  paths: {
    "/auth/login": {
      post: {
        summary: "Authenticate test user",
        description: "Returns a session JWT for sandbox User A, User B, or Admin.",
        security: [],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["email", "password"],
                properties: {
                  email: { type: "string", example: "user_a@demo.internal" },
                  password: { type: "string", example: "pass123" }
                }
              }
            }
          }
        },
        responses: {
          "200": {
            description: "Authentication successful",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    token: { type: "string" },
                    userId: { type: "string" },
                    expiresIn: { type: "number" }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/auth/register": {
      post: {
        summary: "Create sandbox user",
        description: "Registers a new sandbox customer account.",
        security: [],
        responses: {
          "201": { description: "User registered" }
        }
      }
    },
    "/auth/refresh": {
      post: {
        summary: "Refresh session token",
        responses: {
          "200": { description: "Refreshed token" }
        }
      }
    },
    "/users/me": {
      get: {
        summary: "Get current authenticated profile",
        responses: {
          "200": { description: "Current user profile" }
        }
      }
    },
    "/users/{id}": {
      get: {
        summary: "Get user details by ID",
        description: "Returns customer profile. NOTE: Intentionally exposes internal fields in the sandbox testbed.",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string" },
            description: "User identifier (e.g. 101)"
          }
        ],
        responses: {
          "200": {
            description: "User details including potentially overexposed data fields",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    id: { type: "number", example: 101 },
                    name: { type: "string", example: "Rahul Sharma" },
                    email: { type: "string", example: "rahul@demo.internal" },
                    phone: { type: "string", example: "+1-555-0199" },
                    passwordHash: { type: "string", example: "$2b$12$e8x...h9K" },
                    internalNotes: { type: "string", example: "VIP client; risk score tier 0" },
                    ssnLast4: { type: "string", example: "8842" },
                    stripeCustomerId: { type: "string", example: "cus_N924ka82" }
                  }
                }
              }
            }
          }
        }
      },
      put: {
        summary: "Update user profile",
        parameters: [
          { name: "id", in: "path", required: true, schema: { type: "string" } }
        ],
        responses: {
          "200": { description: "Profile updated" }
        }
      }
    },
    "/orders": {
      get: {
        summary: "List user orders",
        responses: {
          "200": { description: "Array of orders" }
        }
      },
      post: {
        summary: "Create new food order",
        responses: {
          "201": { description: "Order created successfully" }
        }
      }
    },
    "/orders/{orderId}": {
      get: {
        summary: "Get order details by orderId",
        description: "VULNERABLE TESTBED: Does not verify that requesting user owns {orderId}. User A can access Order 1002 belonging to User B.",
        parameters: [
          {
            name: "orderId",
            in: "path",
            required: true,
            schema: { type: "string" },
            description: "Order numeric ID"
          }
        ],
        responses: {
          "200": {
            description: "Order payload",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    orderId: { type: "string", example: "1002" },
                    ownerUserId: { type: "string", example: "user_b" },
                    deliveryAddress: { type: "string", example: "742 Evergreen Terrace" },
                    totalAmount: { type: "number", example: 48.50 },
                    items: { type: "array", items: { type: "string" } },
                    status: { type: "string", example: "DELIVERED" }
                  }
                }
              }
            }
          }
        }
      },
      delete: {
        summary: "Cancel order",
        parameters: [
          { name: "orderId", in: "path", required: true, schema: { type: "string" } }
        ],
        responses: {
          "204": { description: "Order cancelled" }
        }
      }
    },
    "/restaurants": {
      get: {
        summary: "List all partner restaurants",
        security: [],
        responses: {
          "200": { description: "List of restaurant objects" }
        }
      }
    },
    "/restaurants/{restaurantId}": {
      get: {
        summary: "Get restaurant profile and business hours",
        security: [],
        parameters: [
          { name: "restaurantId", in: "path", required: true, schema: { type: "string" } }
        ],
        responses: {
          "200": { description: "Restaurant profile" }
        }
      }
    },
    "/restaurants/{restaurantId}/menu": {
      get: {
        summary: "Get restaurant menu catalogue",
        security: [],
        parameters: [
          { name: "restaurantId", in: "path", required: true, schema: { type: "string" } }
        ],
        responses: {
          "200": { description: "Menu items" }
        }
      }
    },
    "/products": {
      get: {
        summary: "Search menu products and dishes",
        description: "VULNERABLE TESTBED: Lacks rate-limit throttle or HTTP 429 backoff headers.",
        security: [],
        parameters: [
          { name: "query", in: "query", required: false, schema: { type: "string" } },
          { name: "limit", in: "query", required: false, schema: { type: "integer" } }
        ],
        responses: {
          "200": { description: "Search results" }
        }
      }
    },
    "/drivers/{driverId}/location": {
      get: {
        summary: "Track live courier GPS coordinates",
        parameters: [
          { name: "driverId", in: "path", required: true, schema: { type: "string" } }
        ],
        responses: {
          "200": { description: "Coordinates payload" }
        }
      }
    },
    "/drivers/status": {
      post: {
        summary: "Courier status transition",
        responses: {
          "200": { description: "Status updated" }
        }
      }
    },
    "/payments/methods": {
      get: {
        summary: "List stored user payment cards",
        responses: {
          "200": { description: "Tokenized cards list" }
        }
      }
    },
    "/payments/charge": {
      post: {
        summary: "Process sandbox payment charge",
        responses: {
          "200": { description: "Payment confirmation" }
        }
      }
    },
    "/coupons/validate": {
      get: {
        summary: "Validate promotional voucher discount",
        security: [],
        parameters: [
          { name: "code", in: "query", required: true, schema: { type: "string" } }
        ],
        responses: {
          "200": { description: "Discount value" }
        }
      }
    },
    "/reviews/{restaurantId}": {
      get: {
        summary: "Public reviews for restaurant",
        security: [],
        parameters: [
          { name: "restaurantId", in: "path", required: true, schema: { type: "string" } }
        ],
        responses: {
          "200": { description: "Reviews list" }
        }
      }
    },
    "/reviews": {
      post: {
        summary: "Submit dining feedback review",
        responses: {
          "201": { description: "Review saved" }
        }
      }
    },
    "/admin/users": {
      get: {
        summary: "List all system users and internal staff",
        description: "VULNERABLE TESTBED: Administrative endpoint with completely missing authentication requirement.",
        security: [],
        responses: {
          "200": {
            description: "Internal staff and customer records leaked without authorization",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      id: { type: "string" },
                      role: { type: "string" },
                      email: { type: "string" }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/admin/metrics": {
      get: {
        summary: "Financial revenue & server analytics",
        description: "Administrative telemetry.",
        responses: {
          "200": { description: "Metrics stream" }
        }
      }
    },
    "/admin/coupons": {
      post: {
        summary: "Issue bulk promotional promo codes",
        responses: {
          "201": { description: "Coupons generated" }
        }
      }
    }
  },
  components: {
    securitySchemes: {
      BearerAuth: {
        type: "http",
        scheme: "bearer",
        bearerFormat: "JWT"
      }
    }
  }
};

export const RAW_FOOD_DELIVERY_JSON = JSON.stringify(FOOD_DELIVERY_OPENAPI_SPEC, null, 2);

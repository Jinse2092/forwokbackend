const express = require("express");
const mongoose = require("mongoose");
const axios = require("axios");

// Helper: fetch and log the access scopes for a Shopify access token (useful for debugging 403s)
async function checkShopifyTokenScopes(shopDomain, token) {
  try {
    const url = `https://${shopDomain}/admin/oauth/access_scopes.json`;
    const resp = await axios.get(url, { headers: { 'X-Shopify-Access-Token': token }, timeout: 8000 });
    const scopes = resp && resp.data && resp.data.access_scopes ? resp.data.access_scopes : null;
    console.warn(`Shopify token scopes for ${shopDomain}:`, scopes);
    return scopes;
  } catch (err) {
    console.error('Failed to fetch Shopify access scopes:', err && (err.response ? (err.response.status + ' ' + JSON.stringify(err.response.data)) : err.message));
    throw err;
  }
}

const app = express();
app.use(express.json());

// Shopify API version (configurable). Default to 2025-01 which matches shop responses.
const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || '2025-01';

// Simple sleep helper
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Normalize courier partner names to Shopify tracking company identifiers
function normalizeCourier(name) {
  if (!name) return '';
  const s = String(name).toLowerCase();
  if (s.includes('delhivery')) return 'delhivery';
  if (s.includes('dtdc')) return 'dtdc';
  if (s.includes('ekart')) return 'ekart';
  if (s.includes('shadowfax')) return 'shadowfax';
  if (s.includes('blueddart') || s.includes('dart') || s.includes('blue dart')) return 'bluedart';
  if (s.includes('post') || s.includes('india post')) return 'india post';
  if (s.includes('fedex')) return 'fedex';
  return s.replace(/[^a-z0-9 ]/g,'').split(' ')[0] || s;
}

// Normalize SKU for matching: trim, lowercase, remove non-alphanumeric
function normalizeSku(s) {
  if (!s) return '';
  return String(s).toLowerCase().replace(/[^a-z0-9]/g, '');
}

// Robust request wrapper that handles Shopify 429s
async function safeAxiosRequest(fn, opts = {}) {
  const maxRetries = opts.maxRetries || 5;
  let attempt = 0;
  while (true) {
    try {
      return await fn();
    } catch (err) {
      attempt++;
      const status = err && err.response && err.response.status;
      if (status === 429 && attempt <= maxRetries) {
        const retryAfter = parseInt(err.response.headers['retry-after'] || err.response.headers['Retry-After'] || '1', 10) || 1;
        const wait = Math.max(1000 * retryAfter, 1000 * Math.pow(2, attempt));
        console.warn('Rate limited by Shopify, retrying after', wait, 'ms');
        await sleep(wait);
        continue;
      }
      throw err;
    }
  }
}

// Helper: create a curl command from axios-style config for reproducing requests
function makeCurl(method, url, headers = {}, body) {
  const headerParts = Object.entries(headers || {}).map(([k, v]) => `-H "${k}: ${String(v).replace(/"/g, '\\"')}"`).join(' ');
  const dataPart = body ? `--data '${typeof body === 'string' ? body : JSON.stringify(body)}'` : '';
  return `curl -X ${method.toUpperCase()} '${url}' ${headerParts} ${dataPart}`.trim();
}

/* -------------------- MongoDB -------------------- */

mongoose.connect(
  "mongodb+srv://LEO:leo112944@cluster0.ye9exkm.mongodb.net/forvoqdb",
  { useNewUrlParser: true, useUnifiedTopology: true }
);

mongoose.connection.once("open", () => {
  console.log("✅ MongoDB connected (Atlas)");
});

/* -------------------- Schemas -------------------- */

const webhookSchema = new mongoose.Schema({}, { strict: false });
const productSchema = new mongoose.Schema({}, { strict: false });
const processedSchema = new mongoose.Schema(
  {
    shopifyOrderId: { type: String, unique: true },
    createdAt: { type: Date, default: Date.now },
  },
  { collection: "processed_shopify_orders" }
);

/* SAFE model loading (prevents overwrite error) */
const Webhook =
  mongoose.models.Webhook || mongoose.model("Webhook", webhookSchema);
const Product =
  mongoose.models.Product || mongoose.model("Product", productSchema);
const ProcessedOrder =
  mongoose.models.ProcessedOrder ||
  mongoose.model("ProcessedOrder", processedSchema);

/* -------------------- Middleware -------------------- */

app.post(
  "/shopify",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      console.log("🔔 Shopify webhook received");

      const payload = JSON.parse(req.body.toString());
      const shopDomain = req.headers["x-shopify-shop-domain"];
      const shopifyOrderId = String(payload.id);

      console.log("🏪 Shopify Store:", shopDomain);
      console.log("🛒 Shopify Order ID:", shopifyOrderId);

      /* ---------- Duplicate protection ---------- */
      const alreadyProcessed = await ProcessedOrder.findOne({
        shopifyOrderId,
      });
      if (alreadyProcessed) {
        console.log("⚠️ Duplicate order ignored");
        return res.status(200).send("Duplicate ignored");
      }

      /* ---------- Merchant resolution (respect webhook filters) ---------- */
      const webhooksMatched = await Webhook.find({ shopifyDomain: shopDomain, active: true });
      if (!webhooksMatched || webhooksMatched.length === 0) {
        console.log("❌ No merchant mapped for shop");
        return res.status(200).send("Unknown merchant");
      }

      // If multiple webhook registrations exist for the same shop, pick the one whose filters match
      let webhook = webhooksMatched[0];
      if (webhooksMatched.length > 1) {
        const shippingForMatch = payload.shipping_address || {};
        const zip = String(shippingForMatch.zip || shippingForMatch.postal_code || '').trim();
        const city = String(shippingForMatch.city || '').toLowerCase();
        const addr = String(shippingForMatch.address1 || '').toLowerCase();
        const province = String(shippingForMatch.province || '').toLowerCase();
        let found = null;
        for (const wh of webhooksMatched) {
          const f = wh.filters || {};
          const pincodes = Array.isArray(f.pincodes) ? f.pincodes.map(p => String(p).trim()) : [];
          const locations = Array.isArray(f.locations) ? f.locations.map(l => String(l).toLowerCase()) : [];
          const states = Array.isArray(f.states) ? f.states.map(s => String(s).toLowerCase()) : [];
          let match = true;
          if (pincodes.length && zip) {
            if (!pincodes.includes(zip)) match = false;
          }
          if (locations.length) {
            if (!locations.some(loc => (city && city.includes(loc)) || (addr && addr.includes(loc)))) match = false;
          }
          if (states.length && province) {
            if (!states.includes(province)) match = false;
          }
          if (match) { found = wh; break; }
        }
        if (found) {
          webhook = found;
          console.log('🔎 Selected webhook by filters for shop', shopDomain, 'merchantId', webhook.merchantId);
        } else {
          console.warn('⚠️ Multiple webhooks for shop found; none matched filters. Using first registered webhook.');
        }
      }

      const merchantId = webhook.merchantId;
      console.log("🆔 Merchant ID:", merchantId);

      /* ---------- Load products ---------- */
      const products = await Product.find({ merchantId });
      console.log("📦 Products in DB:", products.length);
      if (!products.length) {
        try {
          const sample = await Product.find({}).limit(10).select('id sku skus merchantId name').lean();
          console.warn('DEBUG: no products found for merchant; sample product docs from DB:', { merchantId, sampleCount: sample.length, sample });
        } catch (e) {
          console.warn('DEBUG: failed to fetch sample products for inspection', e && e.message);
        }
      }

      const productMap = {};
      products.forEach((p) => {
        const addKey = (val) => {
          const raw = String(val || '').trim();
          if (!raw) return;
          const keyRaw = raw.toLowerCase();
          const keyNorm = normalizeSku(raw);
          if (keyRaw) productMap[keyRaw] = p;
          if (keyNorm) productMap[keyNorm] = p;
        };
        // Primary SKU field (case-insensitive trimmed match) and normalized variant
        addKey(p.sku || p.SKU || p.skuRaw || '');
        // Also map any alternative SKUs stored in `skus` array
        if (Array.isArray(p.skus)) {
          p.skus.forEach(addKey);
        }
      });

      /* ---------- Match line items ---------- */
      const matchedItems = [];
      const unmatchedItems = [];

      for (const item of payload.line_items || []) {
        const rawSku = String(item.sku || item.variant_sku || item.sku_raw || '').trim();
        const lookupKey = rawSku ? rawSku.toLowerCase() : '';
        const product = lookupKey ? productMap[lookupKey] : null;

        if (!product) {
          // Log attempted lookup keys for easier debugging
          try {
            console.warn('DEBUG: SKU lookup failed for webhook item', { shopifySku: rawSku, lookupKey, normalizedLookupKey: normalizeSku(rawSku), merchantId });
          } catch (e) {}
          // No product found in DB for this SKU — still include the item
          const qty = Number(item.quantity) || 1;
          const unknownName = 'Unknown';
          unmatchedItems.push({ shopifySku: item.sku, title: item.title });
          matchedItems.push({
            productId: null,
            sku: rawSku || item.sku,
            name: unknownName,
            quantity: qty,
            weightPerItemKg: 0,
            weightKg: 0,
            unknown: true,
          });
          try {
            console.log('SKU not found in DB, creating unknown item in order payload', { shopifySku: item.sku, name: unknownName });
          } catch (e) {}
          continue;
        }

        const qty = Number(item.quantity) || 1;
        const weightPerItem = Number(product.weightKg || 0);
        const weightKg = weightPerItem * qty;

        const resolvedProductId = (product && product.id) ? String(product.id) : '';

        matchedItems.push({
          productId: resolvedProductId,
          name: product.name,
          quantity: qty,
          weightPerItemKg: weightPerItem,
          weightKg,
        });

        try {
          console.log('SKU match:', { shopifySku: item.sku, productId: resolvedProductId, productName: product.name });
        } catch (e) {}
      }

      console.log("📊 MATCH SUMMARY");
      console.log("✅ Matched Items:", matchedItems);
      console.log("❌ Unmatched Items:", unmatchedItems);
      if (unmatchedItems.length) {
        try {
          console.warn('DEBUG: Unmatched SKUs (webhook)', {
            merchantId,
            shopifyOrderId,
            unmatchedCount: unmatchedItems.length,
            unmatchedItems,
            productKeysSample: Object.keys(productMap || {}).slice(0, 20),
            productMapSize: Object.keys(productMap || {}).length,
          });
        } catch (e) {
          console.warn('DEBUG: failed to stringify unmatchedItems');
        }
      }

      /* ---------- Build order payload ---------- */
      const now = new Date();
      const date = now.toISOString().split("T")[0];
      const time = now.toTimeString().split(" ")[0];

      const shipping = payload.shipping_address || {};

      const orderPayload = {
        id: `shopify-${shopifyOrderId}`,
        merchantId,
        customerName:
          `${shipping.first_name || ""} ${shipping.last_name || ""}`.trim(),
        address: shipping.address1 || "",
        city: shipping.city || "",
        state: shipping.province || "",
        pincode: shipping.zip || "",
        phone: shipping.phone || payload.phone || "",
        items: matchedItems,
        totalWeightKg: matchedItems.reduce(
          (s, i) => s + (i.weightKg || 0),
          0
        ),
        source: "shopify",
        status: "pending",
        date,
        time,
      };

      /* ---------- Send to Orders API ---------- */
      await axios.post(
        "http://localhost:4000/api/orders",
        orderPayload,
        {
          timeout: 8000,
          headers: {
            'x-service-api-token': 'listener@2025'
          }
        }
      );

      /* ---------- Mark processed ---------- */
      await ProcessedOrder.create({ shopifyOrderId });

      console.log("✅ Order forwarded to Orders API");
      res.status(200).send("OK");
    } catch (err) {
      console.error("❌ Shopify webhook error:", err.message);
      res.status(200).send("Webhook error");
    }
  }
);

// Endpoint: listener receives fulfillment notification from server
// Listener endpoint: accept single-order fulfillment requests only. Payload MUST contain merchantId, shopifyOrderId, trackingCode, courier
app.post('/fulfill', async (req, res) => {
  try {
    const { merchantId, shopifyOrderId, trackingCode, courier } = req.body || {};
    console.log('/fulfill received:', { merchantId, shopifyOrderId, trackingCode, courier });
    if (!merchantId || !shopifyOrderId || !trackingCode) return res.status(400).json({ error: 'merchantId, shopifyOrderId and trackingCode required' });

    // Resolve merchant webhook/token
    const webhook = await Webhook.findOne({ merchantId, active: true });
    if (!webhook) return res.status(404).json({ error: 'merchant webhook not found' });
    const shopDomain = webhook.shopifyDomain;
    const token = webhook.signature;

    // Fetch backend order to check shopifyFulfilled lock and get internal id
    let orderResp;
    try {
      orderResp = await axios.get(`http://localhost:4000/api/orders/shopify/${merchantId}/${shopifyOrderId}`, { timeout: 5000 });
    } catch (e) {
      console.error('Fulfill: failed to fetch order from backend', e && (e.response ? (e.response.status + ' ' + JSON.stringify(e.response.data)) : e.message));
      return res.status(500).json({ error: 'Failed to fetch order from backend' });
    }

    const order = orderResp.data;
    // If backend already marked fulfilled, exit immediately
    if (order && order.shopifyFulfilled) {
      console.log('Fulfill: order already marked shopifyFulfilled; skipping', shopifyOrderId);
      return res.json({ message: 'already_fulfilled' });
    }

    // Normalize courier before sending to Shopify
    let normalizedCourier = normalizeCourier(courier || '');
    if (!normalizedCourier) normalizedCourier = 'Other';

    // Use Fulfillment Orders API: GET fulfillment_orders, then POST to fulfillment_orders/{id}/fulfillments.json
    try {
      const foUrl = `https://${shopDomain}/admin/api/${SHOPIFY_API_VERSION}/orders/${shopifyOrderId}/fulfillment_orders.json`;
      console.log('Fulfill: fetching fulfillment_orders for order', { foUrl });
          let foResp;
          try {
            foResp = await safeAxiosRequest(() => axios.get(foUrl, { headers: { 'X-Shopify-Access-Token': token }, timeout: 10000 }));
          } catch (err) {
            // If 403, attempt to fetch token scopes to help debug missing permissions
            try {
              if (err && err.response && err.response.status === 403) {
                console.error('Fulfill: Shopify returned 403 when fetching fulfillment_orders - checking token scopes');
                await checkShopifyTokenScopes(shopDomain, token);
                return res.status(403).json({ error: 'Shopify token missing required scopes for Fulfillment Orders API. Check app scopes and reinstall/regenerate token.' });
              }
            } catch (scopeErr) {
              console.warn('Fulfill: failed while checking token scopes', scopeErr && scopeErr.message);
            }
            throw err;
          }
      const fulfillmentOrders = foResp && foResp.data && foResp.data.fulfillment_orders ? foResp.data.fulfillment_orders : [];
      if (!fulfillmentOrders.length) {
        console.warn('Fulfill: no fulfillment_orders found for order', shopifyOrderId);
        // Fetch the full order for diagnostics (no legacy fulfillment fallback)
        try {
          const orderDetailUrl = `https://${shopDomain}/admin/api/${SHOPIFY_API_VERSION}/orders/${shopifyOrderId}.json`;
          const orderDetailResp = await safeAxiosRequest(() => axios.get(orderDetailUrl, { headers: { 'X-Shopify-Access-Token': token }, timeout: 10000 }));
          try { console.log('Fulfill: order details (diagnostics):', JSON.stringify(orderDetailResp.data)); } catch (e) { console.log('Fulfill: could not stringify order details'); }
        } catch (orderErr) {
          console.error('Fulfill: failed to fetch order details for diagnostics', orderErr && (orderErr.response ? (orderErr.response.status + ' ' + JSON.stringify(orderErr.response.data)) : orderErr.message));
        }
        return res.status(400).json({ error: 'No fulfillment_orders for order' });
      }

      // Use the first fulfillment_order (most common case). Only fulfill that single FO.
      const fo = fulfillmentOrders[0];
      // Create fulfillment using the top-level fulfillments endpoint per Shopify docs
      const fulfillUrl = `https://${shopDomain}/admin/api/${SHOPIFY_API_VERSION}/fulfillments.json`;

      // Log the fulfillment order for diagnostics
      try { console.log('Fulfill: fulfillment_order (fo):', JSON.stringify(fo)); } catch (e) { console.log('Fulfill: could not stringify fo'); }

      // Build payload exactly as requested: only include fulfillment_order_id in the array
      const payload = {
        fulfillment: {
          notify_customer: true,
          tracking_info: {
            number: trackingCode,
            company: normalizedCourier
          },
          line_items_by_fulfillment_order: [
            {
              fulfillment_order_id: fo.id
            }
          ]
        }
      };

      // Log the full JSON payload and curl for reproduction
      try { console.log('Fulfill: POSTing fulfillment (create)'); } catch (e) { /* noop */ }
      try { console.log('Fulfill: payload JSON length', String(JSON.stringify(payload)).length); } catch (e) { /* noop */ }
      const requestHeaders = { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json', Accept: 'application/json' };
      try { console.log('Fulfill: curl:', makeCurl('post', fulfillUrl, requestHeaders, payload)); } catch (e) { /* noop */ }

      let postResp;
      try {
        const reqConfig = { headers: requestHeaders, timeout: 15000 };
        console.log('Fulfill: request config', { url: fulfillUrl, method: 'POST', headers: requestHeaders, timeout: reqConfig.timeout });
        postResp = await safeAxiosRequest(() => axios.post(fulfillUrl, payload, reqConfig));
        console.log('Fulfill: Shopify fulfillment create response', { status: postResp.status, data: postResp && postResp.data ? postResp.data : 'no-body' });
      } catch (err) {
        // Detailed diagnostic logging and surface error (no alternative payloads)
        try {
          if (err && err.response) {
            console.error('Fulfill: Shopify error status:', err.response.status);
            try { console.error('Fulfill: Shopify error headers:', JSON.stringify(err.response.headers)); } catch (e) { console.error('Could not stringify headers'); }
            try { console.error('Fulfill: Shopify error data:', JSON.stringify(err.response.data)); } catch (e) { console.error('Could not stringify data'); }
          } else {
            console.error('Fulfill: Shopify request error (no response):', err && err.message);
          }
        } catch (logErr) {
          console.error('Fulfill: error while logging Shopify error', logErr && logErr.message);
        }

        try {
          if (err && err.config) {
            try { console.log('Fulfill: axios config.headers:', JSON.stringify(err.config.headers)); } catch (e) { console.log('Fulfill: axios config.headers (could not stringify)'); }
            try { console.log('Fulfill: axios config.data:', err.config.data ? err.config.data : 'no-data'); } catch (e) { console.log('Fulfill: axios config.data (could not stringify)'); }
            try { console.log('Fulfill: reproduce with curl:', makeCurl(err.config.method || 'post', err.config.url || fulfillUrl, err.config.headers || requestHeaders, err.config.data || payload)); } catch (e) { console.log('Fulfill: could not create curl'); }
          }
        } catch (logErr) {
          console.error('Fulfill: error while logging axios config', logErr && logErr.message);
        }

        // Surface the error to caller
        throw err;
      }

      // Mark order fulfilled on backend to create a lock (atomic endpoint)
      try {
        // Use internal order id to mark
        const internalId = order.id || order._id;
        if (internalId) {
          const markUrl = `http://localhost:4000/api/orders/${internalId}/shopify-fulfilled`;
          const markResp = await axios.post(markUrl, {}, { headers: { 'x-service-api-token': 'listener@2025' }, timeout: 5000 });
          console.log('Fulfill: backend mark-shopify-fulfilled response', { status: markResp.status, data: markResp && markResp.data ? markResp.data : 'no-body' });
        }
      } catch (markErr) {
        console.warn('Fulfill: failed to mark order fulfilled on backend', markErr && (markErr.response ? (markErr.response.status + ' ' + JSON.stringify(markErr.response.data)) : markErr.message));
      }

      // Also update backend with tracking code and mark as packed
      try {
        const internalId = order.id || order._id;
        if (internalId) {
          const trackUrl = `http://localhost:4000/api/orders/${internalId}/tracking-code`;
          await axios.patch(trackUrl, { trackingCode }, { headers: { 'x-service-api-token': 'listener@2025' }, timeout: 5000 });
          const putUrl = `http://localhost:4000/api/orders/${internalId}`;
          await axios.put(putUrl, { status: 'packed', packedAt: new Date().toISOString() }, { headers: { 'x-service-api-token': 'listener@2025' }, timeout: 5000 });
          console.log('Fulfill: backend updated trackingCode and marked packed', internalId);
        }
      } catch (updateErr) {
        console.warn('Fulfill: failed to update backend with tracking/packed', updateErr && (updateErr.response ? (updateErr.response.status + ' ' + JSON.stringify(updateErr.response.data)) : updateErr.message));
      }

      return res.json({ message: 'fulfilled', shopifyResponseStatus: postResp.status, shopifyResponse: postResp.data });
    } catch (err) {
      console.error('Fulfill: failed during fulfillment flow', err && (err.response ? (err.response.status + ' ' + JSON.stringify(err.response.data)) : err.message));
      return res.status(500).json({ error: 'Fulfillment failed', details: err && (err.response ? err.response.data : err.message) });
    }
  } catch (err) {
    console.error('Fulfill endpoint error', err && err.message);
    return res.status(500).json({ error: 'Internal Error' });
  }
});

// Periodic shopify order fetch flow
async function fetchOrdersForMerchant(webhook) {
  const shopDomain = webhook.shopifyDomain;
  const token = webhook.signature;
  const merchantId = webhook.merchantId;
  if (!shopDomain || !token || !merchantId) {
    console.log('Skipping merchant due to missing data', merchantId);
    return;
  }
  try {
    // Compute time window: yesterday 16:00 -> now (local timezone)
    const now = new Date();
    const today4pm = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 16, 0, 0);
    // Start is always yesterday 16:00
    const start = new Date(today4pm.getTime() - 24 * 60 * 60 * 1000);
    const end = now;
    const created_at_min = start.toISOString();
    const created_at_max = end.toISOString();

    const url = `https://${shopDomain}/admin/api/${SHOPIFY_API_VERSION}/orders.json`;
    console.log(`Fetching orders for ${merchantId}@${shopDomain} window ${created_at_min} -> ${created_at_max} (yesterday 16:00 -> now)`);

    const resp = await safeAxiosRequest(() => axios.get(url, { params: { created_at_min, created_at_max, fulfillment_status: 'unfulfilled' }, headers: { 'X-Shopify-Access-Token': token }, timeout: 15000 }));
    const orders = (resp && resp.data && resp.data.orders) ? resp.data.orders : [];
    console.log(`Fetched ${orders.length} orders for ${shopDomain}`);

    for (const o of orders) {
      const shopifyOrderId = String(o.id);
      // Apply webhook-level filters: if the webhook has pincodes/locations/states configured,
      // only process orders that match ALL non-empty filter categories.
      try {
        const f = webhook.filters || {};
        const pincodes = Array.isArray(f.pincodes) ? f.pincodes.map(p => String(p).trim()) : [];
        const locations = Array.isArray(f.locations) ? f.locations.map(l => String(l).toLowerCase()) : [];
        const states = Array.isArray(f.states) ? f.states.map(s => String(s).toLowerCase()) : [];
        const shippingForMatch = o.shipping_address || {};
        const zip = String(shippingForMatch.zip || shippingForMatch.postal_code || '').trim();
        const city = String(shippingForMatch.city || '').toLowerCase();
        const addr = String(shippingForMatch.address1 || shippingForMatch.address2 || '').toLowerCase();
        const province = String(shippingForMatch.province || shippingForMatch.province_code || '').toLowerCase();

        let passes = true;
        if (pincodes.length) {
          if (!zip || !pincodes.includes(zip)) passes = false;
        }
        if (locations.length) {
          if (!(city && locations.some(loc => city.includes(loc)) || addr && locations.some(loc => addr.includes(loc)))) passes = false;
        }
        if (states.length) {
          if (!province || !states.includes(province)) passes = false;
        }
        if (!passes) {
          console.log(`Skipping order ${shopifyOrderId} — does not match webhook.filters for merchant ${webhook.merchantId}`);
          continue;
        }
      } catch (filterErr) {
        console.warn('Error while applying webhook filters, continuing with order', filterErr && filterErr.message);
      }
      console.log(`Processing fetched order ${shopifyOrderId} for merchant ${merchantId}`);
      try {
        console.log('Fetched order summary', { id: shopifyOrderId, line_items_count: (o.line_items || []).length, has_shipping: !!o.shipping_address, fulfillment_status: o.fulfillment_status || null });
      } catch (e) {
        console.log('Could not stringify fetched order summary');
      }
      try {
        // Check for duplicate in backend
        try {
          const existsResp = await axios.get(`http://localhost:4000/api/orders/shopify/${merchantId}/${shopifyOrderId}`, { timeout: 5000 });
          console.log(`Exists check for ${shopifyOrderId}: status=${existsResp.status}`, existsResp && existsResp.data ? existsResp.data : 'no-body');
          if (existsResp && existsResp.status === 200) {
            console.log(`Order ${shopifyOrderId} already exists in backend; skipping`);
            continue;
          }
        } catch (e) {
          if (e && e.response && e.response.status === 404) {
            console.log(`Order ${shopifyOrderId} not found in backend; will attempt create`);
          } else {
            console.warn('Error checking order existence; will skip this order and continue', e && (e.response ? (e.response.status + ' ' + JSON.stringify(e.response.data)) : e.message));
            continue;
          }
        }

        // Build minimal order payload for backend - include id as 'shopify-<shopifyOrderId>'
        const shipping = o.shipping_address || {};

        // Load products for this merchant so we can map SKUs -> productId/name
        const productsForMerchant = await Product.find({ merchantId });
        console.log('📦 productsForMerchant count:', (productsForMerchant && productsForMerchant.length) || 0);
        if (!productsForMerchant || !productsForMerchant.length) {
          try {
            const sample = await Product.find({}).limit(10).select('id sku skus merchantId name').lean();
            console.warn('DEBUG: productsForMerchant is empty; sample product docs:', { merchantId, sampleCount: sample.length, sample });
          } catch (e) {
            console.warn('DEBUG: failed to fetch sample products for periodic fetch', e && e.message);
          }
        }
        const productMap = {};
        productsForMerchant.forEach(p => {
          const addKey = (val) => {
            const raw = String(val || '').trim();
            if (!raw) return;
            const keyRaw = raw.toLowerCase();
            const keyNorm = normalizeSku(raw);
            if (keyRaw) productMap[keyRaw] = p;
            if (keyNorm) productMap[keyNorm] = p;
          };
          addKey(p.sku || p.SKU || p.skuRaw || '');
          if (Array.isArray(p.skus)) p.skus.forEach(addKey);
        });

        const matchedItems = [];
        const unmatchedItems = [];
        for (const li of (o.line_items || [])) {
          const skuRaw = String(li.sku || li.variant_sku || li.sku_raw || '').trim();
          const skuKey = skuRaw ? skuRaw.toLowerCase() : '';
          const qty = Number(li.quantity || 0) || 1;
          const prod = skuKey ? (productMap[skuKey] || productMap[normalizeSku(skuKey)]) : null;
          if (prod) {
            const weightPerItem = Number(prod.weightKg || 0);
            const resolvedProductId = (prod && prod.id) ? String(prod.id) : '';
            matchedItems.push({ productId: resolvedProductId, name: prod.name, quantity: qty, weightPerItemKg: weightPerItem, weightKg: weightPerItem * qty });
            try { console.log('fetchOrdersForMerchant SKU match', { shopifySku: skuRaw, productId: resolvedProductId, productName: prod.name }); } catch (e) {}
          } else {
            try { console.warn('DEBUG: fetchOrdersForMerchant SKU lookup failed', { shopifySku: skuRaw, skuKey, skuNormalized: normalizeSku(skuRaw), merchantId }); } catch (e) {}
            unmatchedItems.push({ sku: skuRaw, title: li.title || '' });
            matchedItems.push({ sku: skuRaw, name: 'Unknown', quantity: qty });
          }
        }

        if (unmatchedItems.length) {
          try {
            console.warn('DEBUG: fetchOrdersForMerchant unmatched SKUs', {
              merchantId,
              shopifyOrderId,
              unmatchedCount: unmatchedItems.length,
              unmatchedItems,
              productMapSize: Object.keys(productMap || {}).length,
              productKeysSample: Object.keys(productMap || {}).slice(0, 20),
            });
          } catch (e) {
            console.warn('DEBUG: could not stringify fetchOrdersForMerchant unmatched items');
          }
        }

        const payload = {
          id: `shopify-${shopifyOrderId}`,
          shopifyWebhookId: shopifyOrderId,
          merchantId: merchantId,
          customerName: `${shipping.first_name || ''} ${shipping.last_name || ''}`.trim() || (o.contact_email || ''),
          address: shipping.address1 || '',
          city: shipping.city || '',
          state: shipping.province || '',
          pincode: shipping.zip || '',
          phone: shipping.phone || o.phone || '',
          items: matchedItems,
          source: 'shopify'
        };

        try {
          const postResp = await axios.post('http://localhost:4000/api/orders', payload, { timeout: 10000, headers: { 'x-service-api-token': 'listener@2025' } });
          console.log(`Created order in backend for shopifyOrderId=${shopifyOrderId}: status=${postResp.status}`, postResp && postResp.data ? postResp.data : 'no-body');
        } catch (postErr) {
          console.error('Failed to create order in backend for', shopifyOrderId, postErr && (postErr.response ? (postErr.response.status + ' ' + JSON.stringify(postErr.response.data)) : postErr.message));
        }
      } catch (inner) {
        console.error('Error processing shopify order', o && o.id, inner && inner.message);
      }
      // Slightly longer pause between orders to reduce burst and give DB time
      await sleep(500);
    }
  } catch (err) {
    console.error('Error fetching orders for merchant', merchantId, err && (err.response ? (err.response.status + ' ' + JSON.stringify(err.response.data)) : err.message));
  }
}

// Sequentially process all merchants
async function processAllMerchants() {
  try {
    const merchants = await Webhook.find({ active: true });
    console.log(`Processing ${merchants.length} active merchants sequentially`);
    for (const m of merchants) {
      try {
        await fetchOrdersForMerchant(m);
      } catch (e) {
        console.error('Error processing merchant', m && m.merchantId, e && e.message);
      }
      // Small pause between merchants to reduce rate pressure
      await sleep(500);
    }
  } catch (err) {
    console.error('processAllMerchants error', err && err.message);
  }
}

// Kick off on start and every N minutes
const POLL_MINUTES = Number(process.env.SHOPIFY_POLL_MINUTES || 15);
(async () => {
  try {
    await processAllMerchants();
    setInterval(() => {
      processAllMerchants().catch(e => console.error('Periodic fetch error', e));
    }, POLL_MINUTES * 60 * 1000);
  } catch (e) {
    console.error('Initial merchant processing failed', e && e.message);
  }
})();

/* -------------------- Health -------------------- */

app.get("/", (req, res) => {
  res.send("Shopify listener running");
});

const PORT = 9001;
app.listen(PORT, () => {
  console.log(`🚀 Shopify listener listening on port ${PORT}`);
});

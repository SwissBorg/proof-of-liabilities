import Decimal from "decimal.js";

import { webcrypto } from "crypto";
const { subtle } = webcrypto;

// Required to provide precise computation of currency balances
Decimal.set({
  precision: 1000,
  toExpNeg: -1000,
  toExpPos: 1000,
});

// Core hash function taking a string as input and returning an hexstring hash value
async function hash(input: string) {
  const ec = new TextEncoder();
  const digest = await subtle.digest("SHA-256", ec.encode(input));
  return Buffer.from(digest).toString("hex");
}

// Concatenation with ',' separator of strings
// Non-async so that we can inline such calls
function concat(...args: string[]) {
  return Array.prototype.slice.call(args).join(",");
}

// Core Key derivation function
// Input parameters key, ctx and output are strings
async function kdf(key: string, ctx: string) {
  const ec = new TextEncoder();
  const keyData = await subtle.importKey(
    "raw",
    ec.encode(key),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );

  const digest = await subtle.sign(
    {
      name: "HMAC",
    },
    keyData,
    ec.encode(ctx),
  );

  return Buffer.from(digest).toString("hex");
}

// Derivation of Audit nonce
// userCred, auditId and output are strings
async function auditNonceDerive(userCred: string, auditId: string) {
  return await kdf(
    userCred,
    concat("SB PoL - Audit nonce derivation", auditId),
  );
}

// Derivation of Merkle tree nonce
// auditNonce, currency and output are strings
async function merkleTreeNonceDerive(auditNonce: string, currency: string) {
  return await kdf(
    auditNonce,
    concat("SB PoL - Currency Merkle tree nonce derivation", currency),
  );
}

// Derivation of leaf nonce
// mtNonce is a string, leafIndex is an integer (js number), output is a string
async function leafNonceDerive(mtNonce: string, leafIndex: number) {
  return await kdf(
    mtNonce,
    concat("SB PoL - Leaf nonce derivation", leafIndex.toString()),
  );
}

// Leaf hash computation
// leafNonce and userId are string and liability is Decimal
async function leafHashDerive(
  leafNonce: string,
  userId: string,
  liability: Decimal,
) {
  return await hash(concat("leaf", leafNonce, userId, liability.toString()));
}

// Derivation of parent hash based on children
// leftBal: Decimal, rightBal: Decimal, leftHash: str, rightHash: str, output: str
async function innerHashDerive(
  leftBal: Decimal,
  rightBal: Decimal,
  leftHash: string,
  rightHash: string,
) {
  return await hash(
    concat(
      "inner",
      leftBal.toString(),
      rightBal.toString(),
      leftHash,
      rightHash,
    ),
  );
}

// Direct derivation of leaf hash from all user-related parameters
// All inputs are strings except leafIndex is an integer (js number) and liability is Decimal
export async function fullLeafHashDerive(
  userCred: string,
  auditId: string,
  currency: string,
  leafIndex: number,
  userId: string,
  liability: Decimal,
) {
  const auditNonce = await auditNonceDerive(userCred, auditId);
  const mtNonce = await merkleTreeNonceDerive(auditNonce, currency);
  const leafNonce = await leafNonceDerive(mtNonce, leafIndex);

  return await leafHashDerive(leafNonce, userId, liability);
}

interface NodeLeaf {
  liability: Decimal;
  digest: string;
}

interface NodeLeafWithCurrency extends NodeLeaf {
  currency: string;
}

interface MaybeEmptyNodeLeaf {
  liability: Decimal | null;
  digest: string | null;
}

// Verification of the audit commitment hash derived from the Merkle tree root nodes (audit partition commitments)
// Return boolean
export async function audCommHashCheck(
  partIdToData: Map<string, NodeLeafWithCurrency>,
  auditHash: string,
) {
  let input = "SB PoL - Audit commitment hash";
  const auditIdToDataEntries = Array.from(partIdToData, ([auditId, value]) => ({
    auditId,
    value,
  }));
  auditIdToDataEntries.sort((a, b) => {
    if (a.value.currency.toUpperCase() < b.value.currency.toUpperCase()) {
      return -1;
    } else {
      return 1;
    }
  });

  auditIdToDataEntries.forEach((node) => {
    input = concat(
      input,
      node.auditId.toString(),
      node.value.liability.toString(),
      node.value.digest,
    );
  });

  const computedHash = await hash(input);

  if (auditHash !== computedHash) {
    console.log("The audit commitment hash does not match.");
    console.log("Audit Hash: " + auditHash);
    console.log("Computed Hash: " + computedHash);
    return false;
  }

  return true;
}

// Build the Merkle tree and output an array of 'NodeLeaf' (liability: , digest: )
// Input: array of elements of type 'NodeLeaf'
export async function buildMerkleTree(leaves: NodeLeaf[]) {
  const n = leaves.length;
  const tree: MaybeEmptyNodeLeaf[] = leaves.map((a) => ({ ...a }));

  for (let i = 0; i < n - 1; i++) {
    tree.unshift({
      liability: null,
      digest: null,
    });
  }

  for (let i = n - 2; i >= 0; i--) {
    const left = tree[2 * i + 1];
    const right = tree[2 * i + 2];
    if (
      left.liability !== null &&
      right.liability !== null &&
      left.digest !== null &&
      right.digest !== null
    ) {
      tree[i].digest = await innerHashDerive(
        left.liability,
        right.liability,
        left.digest,
        right.digest,
      );
      tree[i].liability = left.liability.plus(right.liability);
    }
  }

  return tree;
}

// leafNode: NodeLeaf object ({liability: Decimal , digest: hexString})
// leafIndex: position of the leaf (zero-based and left-to-right numbering)
// witnesses: array of node objects to reconstruct path up to the root. Root is included here.
// Warning: No validation that the root hash is correct here, i.e., with respect to the audit commitment hash.
// Output: boolean
export async function validateProof(
  leafNode: NodeLeaf,
  leafIndex: number,
  witnesses: NodeLeaf[],
) {
  const d = witnesses.length - 1;
  if (d < 1) {
    console.log("The number of witnesses is too small.");
    return false;
  }

  let nodeLia = leafNode.liability;
  if (!nodeLia.isPositive()) {
    console.log("The user liability is non-positive.");
    return false;
  }

  let nodeHash = leafNode.digest;
  let treeIdx = leafIndex + Math.pow(2, d) - 1;

  for (let i = 0; i < d; i++) {
    const witLia = witnesses[i].liability;
    const witHash = witnesses[i].digest;

    if (!witLia.isPositive()) {
      console.log("The witness " + i + "is non-positive.");
      return false;
    }

    if (treeIdx % 2 == 1) {
      nodeHash = await innerHashDerive(nodeLia, witLia, nodeHash, witHash);
    } else {
      nodeHash = await innerHashDerive(witLia, nodeLia, witHash, nodeHash);
    }

    nodeLia = nodeLia.plus(witLia);
    treeIdx = Math.floor((treeIdx - 1) / 2);
  }

  if (!nodeLia.equals(witnesses[d].liability)) {
    console.log("Merkle Root tree liability does not match.");
    return false;
  }

  if (nodeHash !== witnesses[d].digest) {
    console.log("Merkle Root tree hash does not match.");
    console.log("Computed hash: " + nodeHash);
    console.log("Provided hash: " + witnesses[d].digest);
    return false;
  }

  return true;
}

export interface AuditRootInterface {
  audit: {
    commitment: {
      digest: string;
    };
    id: string;
    partitions: [
      {
        commitment: NodeLeaf;
        currency: string;
        id: string;
      },
    ];
    time: string;
  };
}

export interface UserLiabilitiesInterface {
  user_id: string;
  audit_id: string;
  liabilities: {
    audit_partition_id: string;
    liability: Decimal;
    proof: {
      leaf_index: number;
      nonce: string;
      witnesses: NodeLeaf[];
    };
  }[];
}

// Inputs: user credential as string
//         JSON object containing all liabilities of a user
//         JSON object containing all audit-level data such as audit commitment hash and Merkle tree root nodes.
// Outputs: array with 2 elements. One boolean telling whether the liabilities are valid.
//          A second one which is a hashmap between currencies and user liability.
export async function validateUserLiabilities(
  userCred: string,
  auditRootData: AuditRootInterface,
  userLiabilities: UserLiabilitiesInterface,
) {
  // Check that the auditId is the same in both JSON files.
  if (userLiabilities["audit_id"] !== auditRootData["audit"]["id"]) {
    console.log("Both auditIds do not match.");
    return [false, null];
  }

  const auditHash = auditRootData["audit"]["commitment"]["digest"];
  const auditPartitions = auditRootData["audit"]["partitions"];

  // Populate a Map between an audit partition id (identifier for a Merkle tree of a given currency)
  // and an object containing the Merkle tree relevant data: (currency, liability, digest).
  const partIdToData = new Map();
  auditPartitions.forEach((part) =>
    partIdToData.set(part["id"], {
      currency: part["currency"],
      liability: part["commitment"]["liability"],
      digest: part["commitment"]["digest"],
    }),
  );

  // Validation of all Merkle tree commitments against the audit commitment hash.
  const auditComOk = await audCommHashCheck(partIdToData, auditHash);

  if (!auditComOk) {
    return [false, null];
  }

  const userOutput = new Map();
  const auditId = userLiabilities["audit_id"];
  const userId = userLiabilities["user_id"];

  // Process each user liability: validate and accumulate into userOutput Map.
  for (const liab of userLiabilities["liabilities"]) {
    const partitionData = partIdToData.get(liab["audit_partition_id"]);
    const currency = partitionData.currency;

    // Construct the leaf node.
    const leafHash = await fullLeafHashDerive(
      userCred,
      auditId,
      currency,
      liab["proof"]["leaf_index"],
      userId,
      liab["liability"],
    );

    const leafNode = {
      liability: new Decimal(liab["liability"]),
      digest: leafHash,
    };

    const witnesses = liab["proof"]["witnesses"].map((val) => ({
      liability: new Decimal(val["liability"]),
      digest: val["digest"],
    }));

    // Append the root of Merkle tree (partition) to the list of witnesses.
    witnesses.push({
      liability: new Decimal(partitionData.liability),
      digest: partitionData.digest,
    });

    // Check inclusion proof for this leaf node
    const res = await validateProof(
      leafNode,
      liab["proof"]["leaf_index"],
      witnesses,
    );

    if (!res) {
      return [false, null];
    }

    // Accumulate liability
    if (userOutput.has(currency)) {
      userOutput.set(
        currency,
        userOutput.get(currency).plus(leafNode.liability),
      );
    } else {
      userOutput.set(currency, leafNode.liability);
    }
  }

  return [true, userOutput];
}

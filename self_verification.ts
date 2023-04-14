import Decimal from "decimal.js";
Decimal.set({
  precision: 1000,
  toExpNeg: -1000,
  toExpPos: 1000
})
import { validateUserLiabilities, AuditRootInterface, UserLiabilitiesInterface } from "./merkle"

const fetchAuditRoots = async (auditId:string): Promise<AuditRootInterface> => {
  const auditRootsUrl = `https://app.swissborg.io/solvency/v1/audit/${auditId}`
  const auditRootsResponse = await fetch(auditRootsUrl, {
    headers: {
      "accept": "application/json",
    }
  });
  if (!auditRootsResponse.ok) {
    throw new Error("incorrect AUDIT_ID")
  }

  const auditRoots:AuditRootInterface = await auditRootsResponse.json()
  return auditRoots
}

const fetchUserLiabilities = async (auditId:string, auditCredentialId:string): Promise<UserLiabilitiesInterface> => {
  const userLiabilitiesUrl = `https://app.swissborg.io/solvency/v1/audit/${auditId}/user-liabilities`
  const userLiabilitiesResponse = await fetch(userLiabilitiesUrl, {
    method: "POST",
    headers: {
      "accept": "application/json",
      "content-type": "application/json",    
    },
    body: JSON.stringify({ credential: auditCredentialId }),
  });
  if (!userLiabilitiesResponse.ok) {
    throw new Error("incorrect AUDIT_CREDENTIAL_ID")
  }

  const userLiabilities:UserLiabilitiesInterface = await userLiabilitiesResponse.json()
  return userLiabilities
}

const main = async () => {
  const auditCredentialId = process.argv[2]
  if (!auditCredentialId) { throw new Error("missing AUDIT_CREDENTIAL_ID"); }

  const auditId = process.argv[3]
  if (!auditId) { throw new Error("missing AUDIT_ID"); }

  const userLiabilities = await fetchUserLiabilities(auditId, auditCredentialId)

  const auditRoots = await fetchAuditRoots(auditId)

  const inclusionProof = await validateUserLiabilities(auditCredentialId, auditRoots, userLiabilities)
  if (!inclusionProof[0]) { throw new Error("validation error") }
  return inclusionProof[1]
}

main().then(console.table).catch(console.error)

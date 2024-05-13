import Decimal from "decimal.js";
import { describe, expect, test } from "@jest/globals";

import _userLiabJson_1 from "./testData/userLiab_1.json";
import _auditRootsJson_1 from "./testData/auditRoots_1.json";
import _userLiabJson_2 from "./testData/userLiab_2.json";
import _auditRootsJson_2 from "./testData/auditRoots_2.json";
import _userLiabJson_3 from "./testData/userLiab_3.json";
import _auditRootsJson_3 from "./testData/auditRoots_3.json";
import _userLiabJson_4 from "./testData/userLiab_4.json";
import _auditRootsJson_4 from "./testData/auditRoots_4.json";
import _userLiabJson_5 from "./testData/userLiab_5.json";
import _auditRootsJson_5 from "./testData/auditRoots_5.json";
import _userLiabJson_6 from "./testData/userLiab_6.json";
import _auditRootsJson_6 from "./testData/auditRoots_6.json";
import _userLiabJson_7 from "./testData/userLiab_7.json";
import _auditRootsJson_8 from "./testData/auditRoots_7.json";
import _auditRootsJson_9 from "./testData/auditRoots_8.json";

import {
  audCommHashCheck,
  AuditRootInterface,
  buildMerkleTree,
  fullLeafHashDerive,
  UserLiabilitiesInterface,
  validateProof,
  validateUserLiabilities,
} from "./merkle";

const userLiabJson_1 = _userLiabJson_1 as unknown as UserLiabilitiesInterface;
const auditRootsJson_1 = _auditRootsJson_1 as unknown as AuditRootInterface;

const userLiabJson_2 = _userLiabJson_2 as unknown as UserLiabilitiesInterface;
const auditRootsJson_2 = _auditRootsJson_2 as unknown as AuditRootInterface;

const userLiabJson_3 = _userLiabJson_3 as unknown as UserLiabilitiesInterface;
const auditRootsJson_3 = _auditRootsJson_3 as unknown as AuditRootInterface;

const userLiabJson_4 = _userLiabJson_4 as unknown as UserLiabilitiesInterface;
const auditRootsJson_4 = _auditRootsJson_4 as unknown as AuditRootInterface;

const userLiabJson_5 = _userLiabJson_5 as unknown as UserLiabilitiesInterface;
const auditRootsJson_5 = _auditRootsJson_5 as unknown as AuditRootInterface;

const userLiabJson_6 = _userLiabJson_6 as unknown as UserLiabilitiesInterface;
const auditRootsJson_6 = _auditRootsJson_6 as unknown as AuditRootInterface;

const userLiabJson_7 = _userLiabJson_7 as unknown as UserLiabilitiesInterface;

const auditRootsJson_8 = _auditRootsJson_8 as unknown as AuditRootInterface;

const auditRootsJson_9 = _auditRootsJson_9 as unknown as AuditRootInterface;

// Required to provide precise computation of currency balances
Decimal.set({
  precision: 1000,
  toExpNeg: -1000,
  toExpPos: 1000,
});

describe("Proof of solvency", () => {
  test("Full leaf hash derive", async () => {
    const leafHash = await fullLeafHashDerive(
      "AAAAAAAAAAAAAAAAAAAAAA",
      "SBPOL20221224",
      "BTC",
      0,
      "20000000000000000000000000000000",
      new Decimal("1.2"),
    );
    expect(leafHash).toBe(
      "268f465e7d52d00ecb4e7eea67efa26a29073e7fc808ffd62e45413f5ea2160f",
    );
  });

  test("Audit commitment hash Ok", async () => {
    const auditIdToData = new Map(
      _auditRootsJson_6.audit.partitions.map((audit) => [
        audit.id,
        {
          currency: audit.currency,
          liability: new Decimal(audit.commitment.liability),
          digest: audit.commitment.digest,
        },
      ]),
    );
    const commitsMatch = await audCommHashCheck(
      auditIdToData,
      _auditRootsJson_6.audit.commitment.digest,
    );
    expect(commitsMatch).toBeTruthy();
  });

  test("Audit commitment hash Ok 2", async () => {
    const auditIdToData = new Map(
      auditRootsJson_8.audit.partitions.map((audit) => [
        audit.id,
        {
          currency: audit.currency,
          liability: new Decimal(audit.commitment.liability),
          digest: audit.commitment.digest,
        },
      ]),
    );
    const commitsMatch = await audCommHashCheck(
      auditIdToData,
      auditRootsJson_8.audit.commitment.digest,
    );
    expect(commitsMatch).toBeTruthy();
  });

  test("Build Merkle tree", async () => {
    const expectedTree = [
      {
        liability: new Decimal(650.3057523),
        digest:
          "250c240f6478ca71dcc623753efbbb5952514a225323d7c7153c87424aa18f74",
      },
      {
        liability: new Decimal(263.5596723),
        digest:
          "343d351892e5049ae79b84fb1210d05ea44d3d0b69990ffbe598e634fa0f41fc",
      },
      {
        liability: new Decimal(386.74608),
        digest:
          "5471bbed700db2385e03a18302d456547fd8e2220b2ddcc882c456a6ae8c68f8",
      },
      {
        liability: new Decimal(7.7644723),
        digest:
          "77933b1f697622b5660c7be3fe52fb253aca11a9568fc4735fa73fc294fb5585",
      },
      {
        liability: new Decimal(255.7952),
        digest:
          "6d5013bdd8364d12fe83ff228c72f528b124cc507bcbeebf3fedf5907dda530b",
      },
      {
        liability: new Decimal(377.69068),
        digest:
          "b97a1c1bb1bc42351d53702e0801e27dc712ad1e265d3bee8e048e73c03d3494",
      },
      {
        liability: new Decimal(9.0554),
        digest:
          "bc17b9eb4ebf84a8b73a555f2a334da4b753ae0fce6485bb602de7f5551f3d41",
      },
      {
        liability: new Decimal(2.542),
        digest:
          "876c9e7f5222d843ab1b4c00b4d856ad9cfa222e28a2e5792da8b28992a3ff8d",
      },
      {
        liability: new Decimal(5.2224723),
        digest:
          "4e16ff8cda628474156680c4640fce27093a1a012bd588020f1d47c3ddc7e80c",
      },
      {
        liability: new Decimal(7.45),
        digest:
          "a5f2a333f391626b31567972d3b91c8079016f93c0590c47f39e68da0d21f670",
      },
      {
        liability: new Decimal(248.3452),
        digest:
          "0b727574d0d3bb35fa6de5433bb4993e14abba3daf45ec737ab00b9d7bf51f13",
      },
      {
        liability: new Decimal(375.34534),
        digest:
          "8aa9aa3718f2e89833fe21d2948786c5982600a3f6e3945a2f2624d4ae577869",
      },
      {
        liability: new Decimal(2.34534),
        digest:
          "54e0ac1f0a1596cfbba2cacb95ea6d159f66abcb6fee488e13d9bf22f116e3ec",
      },
      {
        liability: new Decimal(6.9524),
        digest:
          "8ae884c6678476a8b4be466920c94842d5a458895c028796644f0b582554cb17",
      },
      {
        liability: new Decimal(2.103),
        digest:
          "9020c9622c0328d7094f4b249f04c8fe6ed1e17caddced104305e680493957ea",
      },
    ];
    const jsonLeaves = [
      {
        liability: 2.542,
        digest:
          "876c9e7f5222d843ab1b4c00b4d856ad9cfa222e28a2e5792da8b28992a3ff8d",
      },
      {
        liability: 5.2224723,
        digest:
          "4e16ff8cda628474156680c4640fce27093a1a012bd588020f1d47c3ddc7e80c",
      },
      {
        liability: 7.45,
        digest:
          "a5f2a333f391626b31567972d3b91c8079016f93c0590c47f39e68da0d21f670",
      },
      {
        liability: 248.3452,
        digest:
          "0b727574d0d3bb35fa6de5433bb4993e14abba3daf45ec737ab00b9d7bf51f13",
      },
      {
        liability: 375.34534,
        digest:
          "8aa9aa3718f2e89833fe21d2948786c5982600a3f6e3945a2f2624d4ae577869",
      },
      {
        liability: 2.34534,
        digest:
          "54e0ac1f0a1596cfbba2cacb95ea6d159f66abcb6fee488e13d9bf22f116e3ec",
      },
      {
        liability: 6.9524,
        digest:
          "8ae884c6678476a8b4be466920c94842d5a458895c028796644f0b582554cb17",
      },
      {
        liability: 2.103,
        digest:
          "9020c9622c0328d7094f4b249f04c8fe6ed1e17caddced104305e680493957ea",
      },
    ];

    let testLeaves = [];
    for (const element of jsonLeaves) {
      testLeaves.push({
        liability: new Decimal(element.liability),
        digest: element.digest,
      });
    }

    const testTree = await buildMerkleTree(testLeaves);

    expect(testTree).toEqual(expectedTree);
  });

  test("Validate proof", async () => {
    const witnesses = [
      {
        liability: new Decimal("2.34534"),
        digest:
          "54e0ac1f0a1596cfbba2cacb95ea6d159f66abcb6fee488e13d9bf22f116e3ec",
      },
      {
        liability: new Decimal("9.0554"),
        digest:
          "bc17b9eb4ebf84a8b73a555f2a334da4b753ae0fce6485bb602de7f5551f3d41",
      },
      {
        liability: new Decimal("263.5596723"),
        digest:
          "343d351892e5049ae79b84fb1210d05ea44d3d0b69990ffbe598e634fa0f41fc",
      },
      {
        liability: new Decimal("650.3057523"),
        digest:
          "250c240f6478ca71dcc623753efbbb5952514a225323d7c7153c87424aa18f74",
      },
    ];

    const leafNode = {
      liability: new Decimal("375.34534"),
      digest:
        "8aa9aa3718f2e89833fe21d2948786c5982600a3f6e3945a2f2624d4ae577869",
    };

    const leafIndex = 4;

    const out = await validateProof(leafNode, leafIndex, witnesses);

    expect(out).toBeTruthy();
  });

  test("Validate user liabilities test data 1", async () => {
    const largerTestOut = await validateUserLiabilities(
      "20000f995b5305144c082ad3443bf4db",
      auditRootsJson_1,
      userLiabJson_1,
    );
    expect(largerTestOut).toEqual([
      true,
      new Map([
        ["GBP", new Decimal("1")],
        ["CHSB", new Decimal("20022")],
      ]),
    ]);
  });

  test("Validate user liabilities test data 2", async () => {
    const largerTestOut = await validateUserLiabilities(
      "z2Ef6hx6QbRdixkL7c8rdBj",
      auditRootsJson_2,
      userLiabJson_2,
    );
    expect(largerTestOut).toEqual([
      true,
      new Map([["USDC", new Decimal("99.70291")]]),
    ]);
  });

  test("Validate user liabilities test data 3", async () => {
    const largerTestOut = await validateUserLiabilities(
      "z2NRjxCKJiWPh3rfdQVyaTS",
      auditRootsJson_3,
      userLiabJson_3,
    );
    expect(largerTestOut).toEqual([
      true,
      new Map([
        ["USDC", new Decimal("288.50251128818010359")],
        ["ETH", new Decimal("1.700273775267302")],
        ["CHSB", new Decimal("4844.269085")],
      ]),
    ]);
  });

  test("Validate user liabilities test data 4", async () => {
    const largerTestOut = await validateUserLiabilities(
      "z2NRjxCKJiWPh3rfdQVyaTS",
      auditRootsJson_4,
      userLiabJson_4,
    );
    expect(largerTestOut).toEqual([
      true,
      new Map([
        ["USDC", new Decimal("288.50251128818010359")],
        ["ETH", new Decimal("1.700273775267302")],
        ["CHSB", new Decimal("4844.269085")],
      ]),
    ]);
  });

  test("Validate user liabilities test data 5", async () => {
    const largerTestOut = await validateUserLiabilities(
      "zLwByd5Jee3VsnEMCaUGeGH",
      auditRootsJson_5,
      userLiabJson_5,
    );
    expect(largerTestOut).toEqual([
      true,
      new Map([["USDC", new Decimal("99.70291")]]),
    ]);
  });

  test("Validate user liabilities test data 6", async () => {
    const largerTestOut = await validateUserLiabilities(
      "D2tVdEWt1MooLsMa6ryPGj",
      auditRootsJson_6,
      userLiabJson_6,
    );
    expect(largerTestOut).toEqual([
      true,
      new Map([
        ["CHSB", new Decimal("44.81425")],
        ["PLN", new Decimal("10")],
        ["EUR", new Decimal("14558")],
      ]),
    ]);
  });

  test("Validate user liabilities test data 7", async () => {
    const largerTestOut = await validateUserLiabilities(
      "PaY746f8DsYiK8s33J33Jk",
      auditRootsJson_6,
      userLiabJson_7,
    );
    expect(largerTestOut).toEqual([
      true,
      new Map([["USDC", new Decimal("99.70291")]]),
    ]);
  });

  test("Validate user liabilities test data 6 - un-ordered audit JSON data", async () => {
    const largerTestOut = await validateUserLiabilities(
      "D2tVdEWt1MooLsMa6ryPGj",
      auditRootsJson_9,
      userLiabJson_6,
    );
    expect(largerTestOut).toEqual([
      true,
      new Map([
        ["CHSB", new Decimal("44.81425")],
        ["PLN", new Decimal("10")],
        ["EUR", new Decimal("14558")],
      ]),
    ]);
  });

  test("Negative test - wrong user credential", async () => {
    const largerTestOut = await validateUserLiabilities(
      "PaY746f8DsYiK8s33J34Jk",
      auditRootsJson_6,
      userLiabJson_7,
    );
    expect(largerTestOut).toEqual([false, null]);
  });

  test("Negative test - Audit commitment hash not Ok", async () => {
    const auditIdToData = new Map(
      _auditRootsJson_6.audit.partitions.map((audit) => [
        audit.id,
        {
          currency: audit.currency,
          liability: new Decimal(audit.commitment.liability),
          digest: audit.commitment.digest,
        },
      ]),
    );
    const auditHash = await audCommHashCheck(
      auditIdToData,
      "badCommitmentDigest",
    );
    expect(auditHash).toBeFalsy();
  });

  test("Negative test - Wrong audit commitment hash - 2", async () => {
    let auditRootsMalformed = JSON.parse(JSON.stringify(auditRootsJson_6));
    auditRootsMalformed["audit"]["commitment"]["digest"] =
      "017a68ca267d6369f24fb749151c143b43c775451e794e0a287887ad31dbb8d2";

    const largerTestOut = await validateUserLiabilities(
      "PaY746f8DsYiK8s33J33Jk",
      auditRootsMalformed,
      userLiabJson_7,
    );
    expect(largerTestOut).toEqual([false, null]);
  });

  test("Negative test - Mismatch of audit ID", async () => {
    let auditRootsMalformed = JSON.parse(JSON.stringify(auditRootsJson_6));
    auditRootsMalformed["audit"]["id"] = "SBPOL20230112";

    const largerTestOut = await validateUserLiabilities(
      "PaY746f8DsYiK8s33J33Jk",
      auditRootsMalformed,
      userLiabJson_7,
    );
    expect(largerTestOut).toEqual([false, null]);
  });

  test("Negative test - Too small number of witnesses", async () => {
    let userLiabMalformed = JSON.parse(JSON.stringify(userLiabJson_7));
    userLiabMalformed["liabilities"][0]["proof"]["witnesses"].splice(0, 15);
    const largerTestOut = await validateUserLiabilities(
      "PaY746f8DsYiK8s33J33Jk",
      auditRootsJson_6,
      userLiabMalformed,
    );
    expect(largerTestOut).toEqual([false, null]);
  });

  test("Negative test - Negative liability", async () => {
    let userLiabMalformed = JSON.parse(JSON.stringify(userLiabJson_7));
    userLiabMalformed["liabilities"][0]["liability"] = "-1.3";
    const largerTestOut = await validateUserLiabilities(
      "PaY746f8DsYiK8s33J33Jk",
      auditRootsJson_6,
      userLiabMalformed,
    );
    expect(largerTestOut).toEqual([false, null]);
  });

  test("Negative test - negative witness", async () => {
    let userLiabMalformed = JSON.parse(JSON.stringify(userLiabJson_7));
    userLiabMalformed["liabilities"][0]["proof"]["witnesses"][0]["liability"] =
      "-2.4";
    const largerTestOut = await validateUserLiabilities(
      "PaY746f8DsYiK8s33J33Jk",
      auditRootsJson_6,
      userLiabMalformed,
    );
    expect(largerTestOut).toEqual([false, null]);
  });

  test("Negative test - wrong Merkle Root liability", async () => {
    let auditRootsMalformed = JSON.parse(JSON.stringify(auditRootsJson_6));
    auditRootsMalformed["audit"]["partitions"][21]["commitment"]["liability"] =
      "559441.38290498058898063";
    auditRootsMalformed["audit"]["commitment"]["digest"] =
      "97c7b2dee729c32fb9ef4d05c4921b5ef0d2d17b4e5842d5a24972d8ab162073";

    const largerTestOut = await validateUserLiabilities(
      "PaY746f8DsYiK8s33J33Jk",
      auditRootsMalformed,
      userLiabJson_7,
    );
    expect(largerTestOut).toEqual([false, null]);
  });
});

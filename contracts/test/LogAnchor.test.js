const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("LogAnchor", function () {
  let logAnchor;
  let owner, other;

  const sampleArgs = () => ({
    batchId: 12345n,
    sourceIdHash: ethers.keccak256(ethers.toUtf8Bytes("node-1")),
    merkleRoot: ethers.keccak256(ethers.toUtf8Bytes("merkle-root-sample")),
    signature: ethers.toUtf8Bytes("fake-ed25519-signature-64-bytes-placeholder-xxxxxxxxxxxxxxxxxxxx"),
    startSeq: 1n,
    endSeq: 100n,
    timestamp: 1117813370n,
    metadataURI: "ipfs://sample-metadata",
  });

  beforeEach(async function () {
    [owner, other] = await ethers.getSigners();
    const LogAnchor = await ethers.getContractFactory("LogAnchor");
    logAnchor = await LogAnchor.deploy();
    await logAnchor.waitForDeployment();
  });

  it("ancre une racine et emet l'evenement RootAnchored", async function () {
    const args = sampleArgs();

    await expect(
      logAnchor.anchorRoot(
        args.batchId,
        args.sourceIdHash,
        args.merkleRoot,
        args.signature,
        args.startSeq,
        args.endSeq,
        args.timestamp,
        args.metadataURI
      )
    )
      .to.emit(logAnchor, "RootAnchored")
      .withArgs(args.batchId, args.sourceIdHash, args.merkleRoot, args.timestamp);
  });

  it("stocke correctement les champs de l'ancrage (getAnchor)", async function () {
    const args = sampleArgs();
    await logAnchor.anchorRoot(
      args.batchId,
      args.sourceIdHash,
      args.merkleRoot,
      args.signature,
      args.startSeq,
      args.endSeq,
      args.timestamp,
      args.metadataURI
    );

    const anchor = await logAnchor.getAnchor(args.batchId);
    expect(anchor.sourceIdHash).to.equal(args.sourceIdHash);
    expect(anchor.merkleRoot).to.equal(args.merkleRoot);
    expect(anchor.startSeq).to.equal(args.startSeq);
    expect(anchor.endSeq).to.equal(args.endSeq);
    expect(anchor.timestamp).to.equal(args.timestamp);
    expect(anchor.metadataURI).to.equal(args.metadataURI);
    expect(anchor.anchoredBy).to.equal(owner.address);
  });

  it("anchorExists() retourne false avant ancrage, true apres", async function () {
    const args = sampleArgs();
    expect(await logAnchor.anchorExists(args.batchId)).to.equal(false);

    await logAnchor.anchorRoot(
      args.batchId,
      args.sourceIdHash,
      args.merkleRoot,
      args.signature,
      args.startSeq,
      args.endSeq,
      args.timestamp,
      args.metadataURI
    );

    expect(await logAnchor.anchorExists(args.batchId)).to.equal(true);
  });

  it("rootExists() detecte une racine deja ancree (utile pour detecter un replay)", async function () {
    const args = sampleArgs();
    expect(await logAnchor.rootExists(args.merkleRoot)).to.equal(false);

    await logAnchor.anchorRoot(
      args.batchId,
      args.sourceIdHash,
      args.merkleRoot,
      args.signature,
      args.startSeq,
      args.endSeq,
      args.timestamp,
      args.metadataURI
    );

    expect(await logAnchor.rootExists(args.merkleRoot)).to.equal(true);
  });

  it("rejette un double ancrage pour le meme batchId (AnchorAlreadyExists)", async function () {
    const args = sampleArgs();
    await logAnchor.anchorRoot(
      args.batchId,
      args.sourceIdHash,
      args.merkleRoot,
      args.signature,
      args.startSeq,
      args.endSeq,
      args.timestamp,
      args.metadataURI
    );

    await expect(
      logAnchor.anchorRoot(
        args.batchId,
        args.sourceIdHash,
        args.merkleRoot,
        args.signature,
        args.startSeq,
        args.endSeq,
        args.timestamp,
        args.metadataURI
      )
    ).to.be.revertedWithCustomError(logAnchor, "AnchorAlreadyExists");
  });

  it("rejette un merkleRoot vide (EmptyMerkleRoot)", async function () {
    const args = sampleArgs();
    await expect(
      logAnchor.anchorRoot(
        args.batchId,
        args.sourceIdHash,
        ethers.ZeroHash,
        args.signature,
        args.startSeq,
        args.endSeq,
        args.timestamp,
        args.metadataURI
      )
    ).to.be.revertedWithCustomError(logAnchor, "EmptyMerkleRoot");
  });

  it("rejette une plage de sequence invalide (endSeq < startSeq)", async function () {
    const args = sampleArgs();
    await expect(
      logAnchor.anchorRoot(
        args.batchId,
        args.sourceIdHash,
        args.merkleRoot,
        args.signature,
        100n,
        1n,
        args.timestamp,
        args.metadataURI
      )
    ).to.be.revertedWithCustomError(logAnchor, "InvalidSequenceRange");
  });

  it("getAnchor() echoue pour un batchId inexistant (AnchorDoesNotExist)", async function () {
    await expect(logAnchor.getAnchor(999999n)).to.be.revertedWithCustomError(
      logAnchor,
      "AnchorDoesNotExist"
    );
  });

  it("totalAnchors s'incremente a chaque ancrage", async function () {
    expect(await logAnchor.totalAnchors()).to.equal(0n);

    const args1 = sampleArgs();
    await logAnchor.anchorRoot(
      args1.batchId,
      args1.sourceIdHash,
      args1.merkleRoot,
      args1.signature,
      args1.startSeq,
      args1.endSeq,
      args1.timestamp,
      args1.metadataURI
    );
    expect(await logAnchor.totalAnchors()).to.equal(1n);

    const args2 = sampleArgs();
    args2.batchId = 67890n;
    args2.merkleRoot = ethers.keccak256(ethers.toUtf8Bytes("autre-root"));
    await logAnchor.anchorRoot(
      args2.batchId,
      args2.sourceIdHash,
      args2.merkleRoot,
      args2.signature,
      args2.startSeq,
      args2.endSeq,
      args2.timestamp,
      args2.metadataURI
    );
    expect(await logAnchor.totalAnchors()).to.equal(2n);
  });

  it("anchoredBy correspond au compte qui a appele anchorRoot, meme si different du deployeur", async function () {
    const args = sampleArgs();
    await logAnchor.connect(other).anchorRoot(
      args.batchId,
      args.sourceIdHash,
      args.merkleRoot,
      args.signature,
      args.startSeq,
      args.endSeq,
      args.timestamp,
      args.metadataURI
    );

    const anchor = await logAnchor.getAnchor(args.batchId);
    expect(anchor.anchoredBy).to.equal(other.address);
  });
});

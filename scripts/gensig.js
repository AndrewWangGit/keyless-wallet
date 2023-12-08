const { sign } = require("@thehubbleproject/bls/dist/mcl");
const ethers = require("ethers");
const { string } = require("hardhat/internal/core/params/argumentTypes");

function padBase64(input) {
  var segmentLength = 4;
  var stringLength = input.length;
  var diff = stringLength % segmentLength;

  if (!diff) {
    return input;
  }

  var padLength = segmentLength - diff;
  var paddedStringLength = stringLength + padLength;
  var buffer = input;

  while (padLength--) {
    buffer += "=";
  }

  return buffer.toString();
}

function plainToBase64(plaintext) {
  return btoa(plaintext);
}

function plainToBase64url(plaintext) {
  return btoa(plaintext)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function base64urlToPlain(base64url) {
  try {
    return atob(padBase64(base64url).replace(/\-/g, "+").replace(/_/g, "/"));
  } catch (e) {
    return "*** wrong format ***";
  }
}

function base64ToPlain(base64) {
  try {
    return atob(padBase64(base64));
  } catch (e) {
    return "*** wrong format ***";
  }
}

function base64ToBase64url(base64) {
  return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function base64urlToBase64(base64url) {
  return base64url.replace(/\-/g, "+").replace(/_/g, "/");
}

function base64ToHex(base64) {
  var binary = atob(base64);
  var hex = "";
  for (var i = 0; i < binary.length; i++) {
    hex += binary[i].toString(16);
  }
  return hex;
}

function stringToHex(string) {
  const base64 = plainToBase64(string);
  const buffer = Buffer.from(base64, "base64");
  const bufString = buffer.toString("hex");
  return bufString;
}

function base64urlToHex(base64url) {
  const buffer = Buffer.from(base64url, "base64url");
  const bufString = buffer.toString("hex");
  return bufString;
  // const base64 = base64url.replace(/\-/g, "+").replace(/_/g, "/");
  // var binary = atob(base64);
  // var hex = "";
  // for (var i = 0; i < binary.length; i++) {
  //   hex += binary[i].toString(16);
  // }
  // return hex;
}

// ["0x5268550111Fd59Bde3FE8ef4Bc24Be68dB2008DD", "0x", "0xb61d27f60000000000000000000000000be71941d041a32fe7df4a61eb2fcff3b03502c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000004d087d28800000000000000000000000000000000000000000000000000000000", 0x30d40, 0x30d40, 0x30d40, 0x30d40, 0x30d40, "signature", "0x"]
const sender = "0x9b1733E52367560dCd8814c5b6575C177725832f";
const nonce = 0;
const hashInitCode = ethers.keccak256("0x");
const hashCallData = ethers.keccak256(
  "0xb61d27f60000000000000000000000000be71941d041a32fe7df4a61eb2fcff3b03502c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000004d087d28800000000000000000000000000000000000000000000000000000000"
);
const callGasLimit = 0x30d40;
const verificationGasLimit = 0x30d40;
const preVerificationGas = 0x30d40;
const maxFeePerGas = 0x30d40;
const maxPriorityFeePerGas = 0x30d40;
const hashPaymasterAndData = ethers.keccak256("0x");

const abi = ethers.AbiCoder.defaultAbiCoder();
const packed = abi.encode(
  [
    "address",
    "uint256",
    "bytes32",
    "bytes32",
    "uint256",
    "uint256",
    "uint256",
    "uint256",
    "uint256",
    "bytes32",
  ],
  [
    sender,
    nonce,
    hashInitCode,
    hashCallData,
    callGasLimit,
    verificationGasLimit,
    preVerificationGas,
    maxFeePerGas,
    maxPriorityFeePerGas,
    hashPaymasterAndData,
  ]
);
const hash = ethers.keccak256(packed);

const userOpHash = ethers.keccak256(
  abi.encode(
    ["bytes32", "address", "uint256"],
    [hash, "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789", 0x5]
  )
);

const message =
  "0x" +
  stringToHex(
    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImU0YWRmYjQzNmI5ZTE5N2UyZTExMDZhZjJjODQyMjg0ZTQ5ODZhZmYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXpwIjoiNjI5MDc1MTQ1ODE0LTBpbDVhZDlkZ2tsYWQ2b2xubGExMG5lYm5xYzVuMnVqLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiNjI5MDc1MTQ1ODE0LTBpbDVhZDlkZ2tsYWQ2b2xubGExMG5lYm5xYzVuMnVqLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTA0NzU1NjYxMTQxMzY0NzM5NTU1IiwiZW1haWwiOiJhbmRyZXcudGoud2FuZ0BnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6InE4VlF0eVl1NnU0bnNWamZCNjdJY1EiLCJub25jZSI6IjB4N2YyNWIzMjliOGMzZTkzNzY4OTEwZjExMTQ0ZGY2NjNmNmYzYmM2NjkzMGY4NDRiNGNhMDcxZmE2NmYwOTM2YiIsImlhdCI6MTcwMTM3NTA2MiwiZXhwIjoxNzAxMzc4NjYyfQ"
  ).toString();
const jwtSignature =
  "0x" +
  base64urlToHex(
    "HeDvARCw8XruXl9XuZw8aj_g624D0NxU70PxYKtGTK6egV1PtzK1yqYIPka_bEgI6BcYx5GVhvz7LlKkT9b8PNteieNhZC_ivxsY6hNqmp4PzfxIUwq1dLrr6OSRw8SFrv2ohyMuawywcLWnn5uON3bhEhLr1LeQyFjBwLp108o98TDVLwccYMAkDriyC8ww8_3w3nMjjzAgNFILGOTBzK0fyd96UttrZ5xfZQpei-W2R1LC__sT9pWHIPMlsLFhYgT5LmWhFp1apT200PQkihUsVeZXcsNkAmBIQ2g8eomps5LC8VWuEcsND3AJoXBJA7QCj8RboOBIhSq4eLPdLw"
  ).toString();

const userOpSig = abi.encode(
  ["bytes", "bytes", "bytes32"],
  [message, jwtSignature, userOpHash]
);

console.log(ethers.isBytesLike(userOpSig));
console.log(abi.decode(["bytes", "bytes", "bytes32"], userOpSig));

// const provider = new ethers.AlchemyProvider(
//   "goerli",
//   "_L0G9JnFSg-0zB6Kr28tcu46woVR8TNM"
// );
// const signer = new ethers.Wallet(
//   "e014da6f52a9fad02d3dabee519123ca6f76d42a2cdbd34bde2b10e217c3ddfb",
//   provider
// );

// const userOpHashBytes = ethers.getBytes(userOpHash);
// signer.signMessage(userOpHashBytes).then((sig) => {
//   console.log("Signature: " + sig);
// });

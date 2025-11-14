// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);

    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/// @title HashTimelockERC20
/// @notice Escrows ERC20 tokens that can be claimed with a hash preimage or refunded after a timelock.
contract HashTimelockERC20 {
    error AlreadyClaimed();
    error AlreadyRefunded();
    error InvalidHash(bytes32 provided);
    error NotBeneficiary(address caller);
    error NotDepositor(address caller);
    error TimelockPending(uint256 unlockTime);
    error TransferFailed();

    event Claimed(bytes32 secret, address indexed beneficiary);
    event Refunded(address indexed depositor);

    IERC20 public immutable token;
    address public immutable depositor;
    address public immutable beneficiary;
    bytes32 public immutable hashlock;
    uint256 public immutable timelock;
    uint256 public immutable amount;

    bool public claimed;
    bool public refunded;

    constructor(
        IERC20 token_,
        address beneficiary_,
        bytes32 hashlock_,
        uint256 timelock_,
        uint256 amount_
    ) {
        require(beneficiary_ != address(0), "beneficiary=0");
        require(hashlock_ != bytes32(0), "hash=0");
        require(timelock_ > block.timestamp, "timelock");
        require(amount_ > 0, "amount=0");

        token = token_;
        depositor = msg.sender;
        beneficiary = beneficiary_;
        hashlock = hashlock_;
        timelock = timelock_;
        amount = amount_;

        if (!token_.transferFrom(msg.sender, address(this), amount_)) {
            revert TransferFailed();
        }
    }

    function claim(bytes32 secret) external {
        if (claimed) revert AlreadyClaimed();
        if (refunded) revert AlreadyRefunded();
        if (msg.sender != beneficiary) revert NotBeneficiary(msg.sender);

        if (keccak256(abi.encodePacked(secret)) != hashlock) {
            revert InvalidHash(secret);
        }

        claimed = true;
        if (!token.transfer(beneficiary, amount)) {
            revert TransferFailed();
        }

        emit Claimed(secret, beneficiary);
    }

    function refund() external {
        if (claimed) revert AlreadyClaimed();
        if (refunded) revert AlreadyRefunded();
        if (msg.sender != depositor) revert NotDepositor(msg.sender);
        if (block.timestamp < timelock) revert TimelockPending(timelock);

        refunded = true;
        if (!token.transfer(depositor, amount)) {
            revert TransferFailed();
        }

        emit Refunded(depositor);
    }
}

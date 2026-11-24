// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: Apache-2.0

package handshake

// Test vector: client static key 32×0x01, server static key 32×0x02,
// client ephemeral 32×0x03, server ephemeral 32×0x04, payloads as in run.
const (
	vectorSessionID = "wBs08tjslkX4ukHVEX86ew"
	vectorC2S       = "94b186270c9f755d37a7be04740eef40a6137e651a4d091a798698a743fb211f"
	vectorS2C       = "ed1a56b4c8e9c0aa9f00ea8f4ec8c0e08aea65968877c9f3a009137b4f18e5d7"
)

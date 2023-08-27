// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{
	ExecError, InstantiateError, MemoryError, MemoryT, SharedState, SyscallHandler, VirtT,
};
use polkavm::{
	Caller, Config, Engine, ExecutionConfig, ExecutionError, Gas, GasMeteringKind, Instance,
	Linker, Module, ModuleConfig, Reg, Trap,
};
use std::{mem, sync::OnceLock};

static ENGINE: OnceLock<Engine> = OnceLock::new();

pub struct Virt {
	/// `Instance<*mut Self>`
	instance: Instance<usize>,
	/// `Option<SyscallHandler<T>>`
	syscall_handler: Option<ErasedSyscallHandler>,
	/// `Option<*mut SharedState<T>>`
	shared_state: Option<usize>,
}

#[derive(Clone)]
pub struct Memory {
	instance: Instance<usize>,
}

type ErasedSyscallHandler = extern "C" fn(
	// &mut SharedState<T>
	state: usize,
	syscall_no: u32,
	a0: u32,
	a1: u32,
	a2: u32,
	a3: u32,
	a4: u32,
	a5: u32,
) -> u64;

fn engine() -> &'static Engine {
	ENGINE.get_or_init(|| {
		let config = Config::new();
		Engine::new(&config).unwrap()
	})
}

impl VirtT for Virt {
	type Memory = Memory;

	fn instantiate(program: &[u8]) -> Result<Self, InstantiateError> {
		let engine = engine();

		let mut module_config = ModuleConfig::new();
		module_config.set_gas_metering(Some(GasMeteringKind::Async));
		let module = match Module::new(&engine, &module_config, program) {
			Ok(module) => module,
			Err(err) => {
				log::error!("Failed to compile polkavm program: {}", err);
				return Err(InstantiateError::InvalidImage)
			},
		};

		let mut linker = Linker::new(&engine);
		linker.func_fallback(on_ecall);
		let instance = match linker.instantiate_pre(&module) {
			Ok(instance) => instance,
			Err(err) => {
				log::error!("Failed to link polkavm program: {}", err);
				return Err(InstantiateError::InvalidImage)
			},
		};

		let instance = instance.instantiate().unwrap();
		let virt = Self { instance, syscall_handler: None, shared_state: None };
		Ok(virt)
	}

	fn execute<T>(
		mut self,
		function: &str,
		syscall_handler: SyscallHandler<T>,
		shared_state: &mut SharedState<T>,
	) -> Result<(), ExecError> {
		let func = match self.instance.get_typed_func::<(), ()>(function) {
			Ok(func) => func,
			Err(err) => {
				log::error!("Failed to find exported function: {}", err);
				return Err(ExecError::InvalidImage);
			},
		};

		self.syscall_handler = Some(unsafe { mem::transmute(syscall_handler) });
		self.shared_state = Some(shared_state as *mut _ as usize);

		let mut execute_config = ExecutionConfig::default();
		execute_config.set_gas(Gas::MAX);
		let outcome = match func.call_ex(&mut (&mut self as *mut _ as usize), (), execute_config) {
			Ok(_) => Ok(()),
			Err(ExecutionError::Trap(_)) => Err(ExecError::Trap),
			Err(ExecutionError::OutOfGas) => Err(ExecError::OutOfGas),
			Err(err) => {
				log::error!("polkavm execution error: {}", err);
				Err(ExecError::Trap)
			},
		};

		self.syscall_handler = None;
		self.shared_state = None;

		outcome
	}

	fn memory(&self) -> Self::Memory {
		Memory { instance: self.instance.clone() }
	}
}

impl MemoryT for Memory {
	fn read(&self, offset: u32, dest: &mut [u8]) -> Result<(), MemoryError> {
		self.instance
			.read_memory_into_slice(offset, dest)
			.map(|_| ())
			.map_err(|_| MemoryError::OutOfBounds)
	}

	fn write(&self, offset: u32, src: &[u8]) -> Result<(), MemoryError> {
		self.instance.write_memory(offset, src).map_err(|_| MemoryError::OutOfBounds)
	}
}

impl Virt {
	fn shared_state(&self) -> &SharedState<()> {
		unsafe { &*(self.shared_state.unwrap() as *const _) }
	}

	fn shared_state_mut(&mut self) -> &mut SharedState<()> {
		unsafe { &mut *(self.shared_state.unwrap() as *mut _) }
	}
}

fn on_ecall(mut caller: Caller<'_, usize>, syscall_no: u32) -> Result<(), Trap> {
	let a0 = caller.get_reg(Reg::A0);
	let a1 = caller.get_reg(Reg::A1);
	let a2 = caller.get_reg(Reg::A2);
	let a3 = caller.get_reg(Reg::A3);
	let a4 = caller.get_reg(Reg::A4);
	let a5 = caller.get_reg(Reg::A5);

	let virt = unsafe { &mut *(*caller.data_mut() as *mut Virt) };

	// sync polkavm gas counter into host
	let gas_left_before = caller.gas_remaining().expect("metering is enabled; qed").get();
	virt.shared_state_mut().gas_left = gas_left_before;

	let result = (virt.syscall_handler.unwrap())(
		virt.shared_state.unwrap(),
		syscall_no,
		a0,
		a1,
		a2,
		a3,
		a4,
		a5,
	);

	// sync host gas counter into polkavm
	let shared_state = virt.shared_state();
	let consume = gas_left_before.saturating_sub(shared_state.gas_left);
	caller.consume_gas(consume);

	if shared_state.exit {
		Err(Trap::default())
	} else {
		caller.set_reg(Reg::A0, result as u32);
		caller.set_reg(Reg::A1, (result >> 32) as u32);
		Ok(())
	}
}

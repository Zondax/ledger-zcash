import Zemu from '@zondax/zemu'

async function takeLastSnapshot(testname: string, index: number, sim: Zemu) {
  await sim.waitUntilScreenIs(sim.getMainMenuSnapshot())
  await sim.takeSnapshotAndOverwrite('.', testname, index)
  sim.compareSnapshots('.', testname, index)
}

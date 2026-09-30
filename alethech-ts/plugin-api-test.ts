import { openAleth } from "./aleth-container.ts";
import {
  acceptPluginWriteback,
  createPluginSession,
  preparePluginRequest,
  reviewPluginWriteback,
} from "./plugin-api.ts";

async function main():Promise<void>{
  const [path,passphrase]=process.argv.slice(2);
  if(!path||!passphrase) throw new Error("usage: plugin-api-test.ts <file.aleth> <passphrase>");

  const opened=await openAleth(path,passphrase);
  const session=await createPluginSession(opened.payload);

  const openai=preparePluginRequest(session,"openai","Use my verified memory",{limit:10});
  const anthropic=preparePluginRequest(session,"anthropic","Use my verified memory",{limit:10});
  const local=preparePluginRequest(session,"local","Use my verified memory",{limit:10});

  const proposal=reviewPluginWriteback(
    session,
    JSON.stringify({
      alethech_writeback:[{
        memory_type:"semantic",
        content:{plugin_fact:"accepted"},
        source:"provider_proposal",
        confidence:0.85,
      }],
    }),
  );

  const updated=await acceptPluginWriteback(session,proposal);
  if(updated.view.entries.length!==session.view.entries.length+1){
    throw new Error("plugin writeback did not add exactly one memory");
  }
  if(updated.view.head===session.view.head) throw new Error("plugin writeback did not advance HEAD");

  let replayRejected=false;
  try{
    await acceptPluginWriteback(updated,proposal);
  }catch{replayRejected=true;}
  if(!replayRejected) throw new Error("stale plugin writeback proposal was replayed");

  const serialized=JSON.stringify({openai,anthropic,local});
  for(const forbidden of ["PRIVATE KEY","signing.key","root.key","recovery.key"]){
    if(serialized.includes(forbidden)) throw new Error(`plugin API leaked ${forbidden}`);
  }

  process.stdout.write(JSON.stringify({
    source_head:session.view.head,
    updated_head:updated.view.head,
    entries_before:session.view.entries.length,
    entries_after:updated.view.entries.length,
    replay_rejected:replayRejected,
  }));
}

main().catch((e)=>{
  console.error(e instanceof Error?e.message:String(e));
  process.exit(1);
});

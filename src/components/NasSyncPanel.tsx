import { useEffect, useState } from "react";
import { invokeBackend, isTauriRuntime } from "../lib/platform";
import type { AccountInfo } from "../types";

interface Status {configured: boolean; origin?: string; mapping?: Record<string,string>; pending?: number; error?: string}
export function NasSyncPanel({accounts}: {accounts: AccountInfo[]}) {
  const [status,setStatus]=useState<Status>({configured:false});
  const [origin,setOrigin]=useState(""); const [pin,setPin]=useState("");
  const [code,setCode]=useState(""); const [password,setPassword]=useState("");
  const [selected,setSelected]=useState<string[]>([]); const [busy,setBusy]=useState(false);
  const [message,setMessage]=useState("");
  const refresh=async()=>setStatus(await invokeBackend<Status>("nas_status"));
  useEffect(()=>{if(!isTauriRuntime())return; void refresh().catch(()=>setMessage("NAS 設定讀取失敗")); const timer=setInterval(()=>void refresh().catch(()=>{}),15000);return()=>clearInterval(timer);},[]);
  if(!isTauriRuntime())return null;
  async function run(action:()=>Promise<unknown>){setBusy(true);setMessage("");try{await action();await refresh();setMessage("已完成");}catch(e){setMessage(String(e));}finally{setBusy(false);setPassword("");setCode("");}}
  const field="w-full rounded border p-2 bg-transparent";
  return <details className="mb-5 rounded-xl border border-gray-200 dark:border-gray-700 p-4">
    <summary className="cursor-pointer font-medium">NAS 自動暖機 · {status.configured?"已配對":"尚未配對"}</summary>
    <div className="mt-4 space-y-3 text-sm">
      <p>手動切換帳號時同步憑證。NAS 管理的帳號不會由 Switcher 自行暖機或刷新 Token。</p>
      {!status.configured?<form className="space-y-3" onSubmit={e=>{e.preventDefault();void run(()=>invokeBackend("nas_pair",{origin,certificateSha256:pin,code}));}}>
        <label className="block">暖機服務 HTTPS 網址<input required type="url" className={field} value={origin} onChange={e=>setOrigin(e.target.value)} placeholder="https://warmup.example.com" /></label>
        <label className="block">服務憑證 SHA-256 指紋<input required className={field} value={pin} onChange={e=>setPin(e.target.value)} /></label>
        <label className="block">一次性配對碼<input required type="password" autoComplete="off" className={field} value={code} onChange={e=>setCode(e.target.value)} /></label>
        <button disabled={busy} className="rounded bg-blue-600 px-4 py-2 text-white">配對 NAS</button>
      </form>:<>
        <p className="break-all">服務：{status.origin}</p>
        <fieldset disabled={busy} className="space-y-2"><legend>選擇要匯入的帳號（先選一個驗收）</legend>
          {accounts.filter(a=>a.auth_mode==="chat_g_p_t").map(a=><label key={a.id} className="flex items-center gap-2"><input type="checkbox" disabled={!!status.mapping?.[a.id]} checked={selected.includes(a.id)||!!status.mapping?.[a.id]} onChange={e=>setSelected(old=>e.target.checked?[...old,a.id]:old.filter(id=>id!==a.id))}/>{a.name}{status.mapping?.[a.id]?" · 已同步":""}</label>)}
        </fieldset>
        <label className="block">NAS 管理密碼（僅供本次匯入）<input type="password" autoComplete="off" className={field} value={password} onChange={e=>setPassword(e.target.value)} /></label>
        <button disabled={busy||!selected.length||!password} className="rounded bg-blue-600 px-4 py-2 text-white disabled:opacity-40" onClick={()=>void run(()=>invokeBackend("nas_import",{accountIds:selected,adminPassword:password}))}>匯入選取帳號</button>
        <p>匯入後預設停用，完成驗收後再到 NAS 管理頁啟用。</p>
        <button disabled={busy} className="rounded border px-4 py-2" onClick={()=>void run(()=>invokeBackend("nas_recover"))}>關閉 Codex 後恢復未完成同步</button>
        {!!status.pending&&<p role="alert">有未完成的切換紀錄，相關帳號保持鎖定。</p>}
      </>}
      {(message||status.error)&&<p role="status" className="break-words">{message||status.error}</p>}
    </div>
  </details>;
}

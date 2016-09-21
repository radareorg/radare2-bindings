(* 
 * R2PIPE 
 *
 * This module (will) provides an API to interact with the radare2
 * commandline interface from Python using a pipe
 *
 *)

open Unix
       
type file_scheme = FILE_LOCAL | FILE_REMOTE
type local_ctx = in_channel * out_channel * in_channel

let bytes_startswith s sub =
  let slen = Bytes.length s in
  let sublen = Bytes.length sub in
  if sublen>slen then false
  else if Bytes.sub_string s 0 sublen = sub then true
  else false
                                  
let get_file_scheme f =
  match (bytes_startswith f "http://") with
  | true -> FILE_REMOTE
  | false -> FILE_LOCAL

let ropen f =
  match (get_file_scheme f) with
  | FILE_LOCAL ->
     let (cout, cin, cerr) = open_process_full f [| |] in
     Some(cout, cin, cerr)
  | FILE_REMOTE -> None

let cmd ctx c =
  let cout, cin, cerr = ctx in
  let () = output_string cin c in
  let cmd_out_descr = Unix.descr_of_in_channel cout in
  let cmd_err_descr = Unix.descr_of_in_channel cerr in
  ()

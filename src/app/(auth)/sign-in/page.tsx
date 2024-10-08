"use client";
import {useSession, signIn, signOut} from "next-auth/react";

export default function SignInForm() {
  const {data: session} = useSession();
  if (session) {
    return (
      <>
        Signed in as {session.user.email} <br />
        <button onClick={() => signOut()}>Sign out</button>
      </>
    );
  }
  return (
    <>
      <h1>Not signed in</h1> <br />
      <button
        className="bg-orange-500 px-3 py-1 m-5 rounded"
        onClick={() => signIn()}
      >
        Sign in
      </button>
    </>
  );
}

async function submitAction(formData) {
  "use server";
  console.log("submitted:", formData.get("name"));
}

export const dynamic = "force-dynamic";

export default function Home() {
  return (
    <form action={submitAction}>
      <input type="text" name="name" />
      <button type="submit">go</button>
    </form>
  );
}

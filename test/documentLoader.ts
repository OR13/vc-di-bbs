export const documentLoader = (id: string)=>{
  const message = "Unsupported id: " + id;
  console.error(message);
  throw new Error(message);
}
import * as bcrypt from 'bcryptjs';

export const hashText = async (
  text: string,
  saltRounds: number = 10,
): Promise<string> => {
  const resutl = await bcrypt.hash(text, saltRounds);


  return resutl;
};

export const compareHash = async (
  text: string,
  hash: string,
): Promise<boolean> => {
 

  const result = await bcrypt.compare(text, hash);
  return result;
};

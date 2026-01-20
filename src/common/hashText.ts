import * as bcrypt from 'bcryptjs';

export const hashText = async (
  text: string,
  saltRounds: number = 10,
): Promise<string> => {
  const resutl = await bcrypt.hash(text, saltRounds);
  console.log('hashPassword shwo me 33333333333', resutl);

  return resutl;
};

export const compareHash = async (
  text: string,
  hash: string,
): Promise<boolean> => {
  console.log(text, hash);

  const result = await bcrypt.compare(text, hash);
  console.log('this is the reuslt :', result);
  return result;
};

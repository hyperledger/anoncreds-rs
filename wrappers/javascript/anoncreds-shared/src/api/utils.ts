export const pushToArray = <T>(obj: T, arr: T[]) => arr[arr.push(obj) - 1]

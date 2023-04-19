import { Kilovolt } from "https://deno.land/x/kilovolt@v8.0.0/mod.ts";
import { Redeem } from "./types.ts";

export class Loyalty {
  /**
   * Listen for redeems
   * @param callback Function to call when someone redeems a reward
   */
  onRedeem(callback: (message: Redeem) => void) {
    return this.kv.subscribeKey("loyalty/ev/new-redeem", (newValue: string) => {
      const message = JSON.parse(newValue) as Redeem;
      callback(message);
    });
  }

  constructor(private readonly kv: Kilovolt) {}
}

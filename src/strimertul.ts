import { Kilovolt } from "https://deno.land/x/kilovolt@v8.0.0/mod.ts";
import { Twitch } from "./twitch/twitch.ts";
import { Loyalty } from "./loyalty/loyalty.ts";

export interface ClientOptions {
  /* Address to connect to (including path), a default will be used if this is not specified */
  address?: string;

  /* If provided, authenticate non-interactively as soon as connection is established */
  password?: string;

  /* If true, authenticate interactively as soon as connection is established */
  interactive?: boolean;

  /* When authenticating interactively, this data is added to the auth message */
  interactiveData?: Record<string, unknown>;
}

/**
 * Strimertül client
 */
export class Strimertul {
  private kv: Kilovolt;

  /**
   * Twitch-related functions
   */
  twitch: Twitch;

  /**
   * Loyalty system functions
   */
  loyalty: Loyalty;

  /**
   * Create a new strimertul client
   * @param options Connection options for authentication
   */
  constructor(options: ClientOptions) {
    this.kv = new Kilovolt(options.address || "ws://localhost:4337/ws", {
      reconnect: true,
      ...options,
    });
    this.twitch = new Twitch(this.kv);
    this.loyalty = new Loyalty(this.kv);
  }

  /**
   * Connects to the strimertül instance. You must call and await this before
   * using any of the other methods!
   */
  connect() {
    return this.kv.connect();
  }
}

export default Strimertul;

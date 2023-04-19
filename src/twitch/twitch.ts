import { Kilovolt } from "https://deno.land/x/kilovolt@v8.0.0/mod.ts";
import {
  ChannelUpdateEvent,
  CheerEvent,
  CustomRewardRedemptionEvent,
  EventSubUnknownEvent,
  FollowEvent,
  RaidEvent,
  ResubscriptionEvent,
  SubscriptionEvent,
  SubscriptionGiftEvent,
  TwitchChatMessage,
} from "./types.ts";

export class Chat {
  constructor(private readonly kv: Kilovolt) {}

  /**
   * Listen for new messages coming from Twitch chat
   * @param callback Function to call when a new message is received
   */
  onMessage(callback: (message: TwitchChatMessage) => void) {
    return this.kv.subscribeKey(
      "twitch/ev/chat-message",
      (newValue: string) => {
        const message = JSON.parse(newValue) as TwitchChatMessage;
        callback(message);
      }
    );
  }

  /**
   * Write a plain text message to chat (emotes supported)
   * @param message Message to write
   */
  writeMessage(message: string) {
    return this.kv.putKey("twitch/@send-chat-message", message);
  }
}

export class EventSub {
  constructor(private readonly kv: Kilovolt) {}

  /**
   * Generic catch-all listener for all EventSub events
   * @param callback Function to call when a new event is received
   */
  onEventSubEvent(callback: (message: EventSubUnknownEvent) => void) {
    return this.kv.subscribeKey(
      "twitch/ev/eventsub-event",
      (newValue: string) => {
        const ev = JSON.parse(newValue) as EventSubUnknownEvent;
        callback(ev);
      }
    );
  }

  /**
   * Listen for new redeems
   * @param callback Function to call when something is redeemed
   */
  onRedeem(callback: (message: CustomRewardRedemptionEvent) => void) {
    return this.onEventSubEvent((ev: EventSubUnknownEvent) => {
      if (
        ev.subscription.type !==
        "channel.channel_points_custom_reward_redemption.add"
      ) {
        return;
      }
      callback(ev as CustomRewardRedemptionEvent);
    });
  }

  /**
   * Listen for new follow events
   * @param callback Function to call when someone follows the channel
   */
  onNewFollow(callback: (message: FollowEvent) => void) {
    return this.onEventSubEvent((ev: EventSubUnknownEvent) => {
      if (ev.subscription.type !== "channel.follow") {
        return;
      }
      callback(ev as FollowEvent);
    });
  }

  /**
   * Listen for new subscriptions
   * @param callback Function to call when someone subscribes for the first time
   */
  onNewSubscription(callback: (message: SubscriptionEvent) => void) {
    return this.onEventSubEvent((ev: EventSubUnknownEvent) => {
      if (ev.subscription.type !== "channel.subscribe") {
        return;
      }
      callback(ev as SubscriptionEvent);
    });
  }

  /**
   * Listen for gifted subscriptions
   * @param callback Function to call when someone gifts a subscription
   */
  onGiftedSubscription(callback: (message: SubscriptionGiftEvent) => void) {
    return this.onEventSubEvent((ev: EventSubUnknownEvent) => {
      if (ev.subscription.type !== "channel.subscription.gift") {
        return;
      }
      callback(ev as SubscriptionGiftEvent);
    });
  }

  /**
   * Listen for returning subscriptions
   * @param callback Function to call when someone renews their subscription
   */
  onResubscription(callback: (message: ResubscriptionEvent) => void) {
    return this.onEventSubEvent((ev: EventSubUnknownEvent) => {
      if (ev.subscription.type !== "channel.subscription.message") {
        return;
      }
      callback(ev as ResubscriptionEvent);
    });
  }

  /**
   * Listen for channel updates
   * @param callback Function to call when channel info (name, game, tags etc) is changed
   */
  onChannelUpdate(callback: (message: ChannelUpdateEvent) => void) {
    return this.onEventSubEvent((ev: EventSubUnknownEvent) => {
      if (ev.subscription.type !== "channel.update") {
        return;
      }
      callback(ev as ChannelUpdateEvent);
    });
  }

  /**
   * Listen for viewers cheering
   * @param callback Function to call when someone cheers some bits
   */
  onCheer(callback: (message: CheerEvent) => void) {
    return this.onEventSubEvent((ev: EventSubUnknownEvent) => {
      if (ev.subscription.type !== "channel.cheer") {
        return;
      }
      callback(ev as CheerEvent);
    });
  }

  /**
   * Listen for incoming raids
   * @param callback Function to call when someone raids the channel
   */
  onRaid(callback: (message: RaidEvent) => void) {
    return this.onEventSubEvent((ev: EventSubUnknownEvent) => {
      if (ev.subscription.type !== "channel.raid") {
        return;
      }
      callback(ev as RaidEvent);
    });
  }
}

export class Twitch {
  /**
   * Twitch chat related functions
   */
  chat: Chat;

  /**
   * Event related functions
   */
  event: EventSub;

  constructor(kv: Kilovolt) {
    this.chat = new Chat(kv);
    this.event = new EventSub(kv);
  }
}

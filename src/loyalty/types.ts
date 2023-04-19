export interface Reward {
  enabled: boolean;
  id: string;
  name: string;
  description: string;
  image: string;
  price: number;
  required_info: string;
  cooldown: number;
}

export interface Redeem {
  username: string;
  display_name: string;
  reward: Reward;
  when: string; // Datetime
  request_text: string;
}

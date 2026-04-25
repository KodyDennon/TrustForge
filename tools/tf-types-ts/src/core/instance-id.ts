import type { ActorType } from "../generated/_common.js";
import { ACTOR_TYPES, ActorIdParseError, formatActorId, splitScheme } from "./actor-id.js";

export class InstanceIdParseError extends ActorIdParseError {}

const ACTOR_TYPE_SET: ReadonlySet<string> = new Set<string>(ACTOR_TYPES);

export interface ParsedInstanceId {
  readonly type: ActorType;
  readonly actorPath: string;
  readonly instancePath: string;
  readonly raw: string;
}

/**
 * Parse an instance URI of the form `tf:instance:<type>:<actor-path>/<instance-path>`.
 *
 * The split between actor-path and instance-path is the last `/` in the URI.
 * Both halves must be non-empty.
 */
export function parseInstanceId(s: string): ParsedInstanceId {
  if (typeof s !== "string") throw new InstanceIdParseError(`expected string, got ${typeof s}`);
  const parts = splitScheme(s);
  if (!parts || parts.kind !== "instance") {
    throw new InstanceIdParseError(`expected tf:instance:<type>:<actor-path>/<instance-path>, got ${JSON.stringify(s)}`);
  }
  if (!ACTOR_TYPE_SET.has(parts.typeSegment)) {
    throw new InstanceIdParseError(`unknown actor type: ${parts.typeSegment}`);
  }
  const split = parts.path.lastIndexOf("/");
  if (split <= 0) {
    throw new InstanceIdParseError(`instance id must contain '/' separating actor and instance: ${s}`);
  }
  const actorPath = parts.path.slice(0, split);
  const instancePath = parts.path.slice(split + 1);
  if (!actorPath || !instancePath) {
    throw new InstanceIdParseError(`empty actor or instance segment in ${s}`);
  }
  return { type: parts.typeSegment as ActorType, actorPath, instancePath, raw: s };
}

export function formatInstanceId(p: { type: ActorType; actorPath: string; instancePath: string }): string {
  if (!ACTOR_TYPE_SET.has(p.type)) throw new InstanceIdParseError(`unknown actor type: ${p.type}`);
  if (!p.actorPath) throw new InstanceIdParseError("instance id actor-path is empty");
  if (!p.instancePath) throw new InstanceIdParseError("instance id instance-path is empty");
  return `tf:instance:${p.type}:${p.actorPath}/${p.instancePath}`;
}

export function toActorId(instanceId: string): string {
  const parsed = parseInstanceId(instanceId);
  return formatActorId({ type: parsed.type, path: parsed.actorPath });
}

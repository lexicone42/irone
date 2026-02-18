import * as path from "node:path";
import { Duration } from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda";
import { Construct } from "constructs";

const DUMMY_BOOTSTRAP = path.join(__dirname, "dummy-bootstrap");

export interface RustLambdaProps {
  /** Logical ID to override on the CfnFunction (for adopting existing stacks). */
  readonly logicalId?: string;
  /** Lambda function description. */
  readonly description?: string;
  /** Memory in MB (default 1024). */
  readonly memorySize?: number;
  /** Timeout in seconds (default 120). */
  readonly timeout?: number;
  /** Explicit function name (required to avoid replacement on adoption). */
  readonly functionName?: string;
  /** Environment variables. */
  readonly environment?: Record<string, string>;
  /**
   * Path to the directory containing the bootstrap binary.
   * Default: a dummy placeholder — real deploys use the deploy script.
   */
  readonly codePath?: string;
}

/**
 * L3 construct for a Rust Lambda on provided.al2023.
 *
 * CDK manages the function definition; actual code deployment is done
 * out-of-band via `scripts/deploy_rust_lambda.sh` (cargo-lambda build + S3 upload).
 * The construct creates a placeholder bootstrap so `cdk synth` succeeds.
 */
export class RustLambda extends Construct {
  public readonly function: lambda.Function;

  constructor(scope: Construct, id: string, props: RustLambdaProps = {}) {
    super(scope, id);

    this.function = new lambda.Function(this, "Handler", {
      functionName: props.functionName,
      runtime: lambda.Runtime.PROVIDED_AL2023,
      handler: "bootstrap",
      code: lambda.Code.fromAsset(props.codePath ?? DUMMY_BOOTSTRAP),
      memorySize: props.memorySize ?? 1024,
      timeout: Duration.seconds(props.timeout ?? 120),
      description: props.description,
      environment: props.environment,
    });

    if (props.logicalId) {
      const cfn = this.function.node.defaultChild as lambda.CfnFunction;
      cfn.overrideLogicalId(props.logicalId);
    }
  }
}

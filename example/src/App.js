import * as React from 'react';

import { StyleSheet, View, Text } from 'react-native';
import { sha256 } from '../../lib/commonjs/index.js';

export default function App() {
  const [result, setResult] = React.useState();
  console.log('result', result, typeof result)

  React.useEffect(() => {
    sha256('string').then(setResult);
  }, []);

  return (
    <View style={styles.container}>
      <Text>Result: {result}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 60,
    height: 60,
    marginVertical: 20,
  },
});
